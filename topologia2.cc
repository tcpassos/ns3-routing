//    Topologia da rede:
//
//    /---> Roteador_1 --x--> Roteador_2
//   /              \           /     \      Todos os enlaces têm custo 1
//  /             ___\_________/       \     com exceção dos enlaces entre o Roteador_1 e o Roteador_4
// (T)           /    \                (R)                         e entre o Roteador_3 e o Roteador_2
//  \           /      \________       /                           que têm custo 2
//   \         /                \     /
//    \---> Roteador_3 --x--> Roteador_4
//
// Após o LINK_DOWN_TIME, o enlace entre o Roteador_1 e o Roteador_2 é derrubado.
// Após o LINK_DOWN_TIME, o enlace entre o Roteador_3 e o Roteador_4 é derrubado.
// Após o LINK_UP_TIME, os enlaces são restaurados.
//
//
// Para rodar a simulação com ambos os protocolos de roteamento, execute:
// (Criar a pasta "resultados" antes de executar o comando)
// ./waf --run "topologia2 --routingProtocol=rip --subfolder=resultados" && ./waf --run "topologia2 --routingProtocol=olsr --subfolder=resultados"
//
// Essa simulação irá gerar arquivos PCAP para cada enlace da rede, que podem ser visualizados com o Wireshark.
// Para mesclar os arquivos PCAP em um único arquivo, execute o comando dentro da pasta onde os arquivos estão:
// mergecap -w topologia2_rip.pcap $(find . -type f -regex "./topologia2_rip.*\.pcap$")
// mergecap -w topologia2_olsr.pcap $(find . -type f -regex "./topologia2_olsr.*\.pcap$")
//
// Podemos visualizar um gráfico estatístico dos pacotes enviados e recebidos com o Wireshark Graph I/O:
// Os filtros recomendados para o gráfico são:
// "Todos os pacotes" - Sem filtros
// "Pacotes de controle de roteamento" - rip || olsr
// "Pacotes UDP da aplicação" - udp.port == 9
// "Pacotes antes da queda" - frame.time <= 100
// "Pacotes durante a queda" - frame.time >= 100 && frame.time <= 200
// "Pacotes após a queda" - frame.time >= 200

#include <sstream>
#include <fstream>
#include <filesystem>
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-routing-table-entry.h"
#include "ns3/olsr-helper.h"
#include <ns3/animation-interface.h>
#include <ns3/point-to-point-helper.h>
#include <ns3/udp-client-server-helper.h>

using namespace ns3;

#define SIMULATION_TIME 300.0
#define UDP_TRANSMISSION_TIME 50.0
#define UDP_PACKET_INTERVAL 0.1
#define UDP_MAX_PACKETS 2000
#define LINK_DOWN_TIME 100.0
#define LINK_UP_TIME 200.0

NS_LOG_COMPONENT_DEFINE("TopologySimulation");
std::map<std::pair<Ptr<Node>, Ptr<Node>>, uint32_t> nodeInterfaceMap;

/**
 * Classe para monitorar a tabela de roteamento de um nó.
 */
class RoutingTableTracker : public Object {
public:
  RoutingTableTracker (Ptr<Node> node) : m_tracking(true), m_node (node) {
    m_lastRoutingTable = GetRoutingTable ();
    Simulator::Schedule (Seconds (1.0), &RoutingTableTracker::CheckRoutingTable, this);
  }

  void StopTracking () {
    m_tracking = false;
  }

  void CheckRoutingTable () {
    if (!m_tracking) {
      return;
    }
    auto currentRoutingTable = GetRoutingTable ();
    if (currentRoutingTable != m_lastRoutingTable) {
      m_lastRoutingTable = currentRoutingTable;
      m_lastChangeTime = Simulator::Now ();
    }
    Simulator::Schedule (Seconds (.1), &RoutingTableTracker::CheckRoutingTable, this);
  }

  Time GetLastChangeTime () const {
    return m_lastChangeTime;
  }

private:
  std::string GetRoutingTable () const {
    auto ipv4 = m_node->GetObject<Ipv4> ();
    auto routing = ipv4->GetRoutingProtocol ();
    std::ostringstream oss;
    auto stream = Create<OutputStreamWrapper> (&oss);
    routing->PrintRoutingTable (stream);
    auto routingTable = oss.str();
    // Remove a primeira linha (que contém o tempo atual)
    auto pos = routingTable.find("\n");
    if (pos != std::string::npos) {
      routingTable = routingTable.substr(pos + 1);
    }
    return routingTable;
  }

  bool m_tracking;
  Ptr<Node> m_node;
  std::string m_lastRoutingTable;
  Time m_lastChangeTime;
};

/**
 * Classe para monitorar a convergência da rede.
 */
class NetworkConvergenceTracker : public Object {
public:
  NetworkConvergenceTracker (NodeContainer routers) {
    for (auto i = routers.Begin (); i != routers.End (); ++i) {
      auto tracker = Create<RoutingTableTracker> (*i);
      m_trackers.push_back (tracker);
    }
  }

  void StopTracking () {
    for (const auto& tracker : m_trackers) {
      tracker->StopTracking();
    }
  }

  Time GetNetworkConvergenceTime () const {
    Time maxTime = Seconds (0);
    for (const auto& tracker : m_trackers) {
      auto lastChangeTime = tracker->GetLastChangeTime ();
      if (lastChangeTime > maxTime) {
        maxTime = lastChangeTime;
      }
    }
    return maxTime;
  }

private:
  std::vector<Ptr<RoutingTableTracker>> m_trackers;
};

/**
 * Cria um nó e o adiciona ao Names.
 */
Ptr<Node> CreateNode (const std::string& name) {
  Ptr<Node> node = CreateObject<Node> ();
  Names::Add (name, node);
  return node;
}

/**
 * Derruba um enlace.
 */
void TearDownLink (Ptr<Node> node1, Ptr<Node> node2) {
  uint32_t interface1 = nodeInterfaceMap[{node1, node2}];
  uint32_t interface2 = nodeInterfaceMap[{node2, node1}];
  node1->GetObject<Ipv4> ()->SetDown (interface1);
  node2->GetObject<Ipv4> ()->SetDown (interface2);
}

/**
 * Restaura um enlace.
 */
void UpLink (Ptr<Node> node1, Ptr<Node> node2) {
  uint32_t interface1 = nodeInterfaceMap[{node1, node2}];
  uint32_t interface2 = nodeInterfaceMap[{node2, node1}];
  node1->GetObject<Ipv4> ()->SetUp (interface1);
  node2->GetObject<Ipv4> ()->SetUp (interface2);
}

/**
 * Imprime as estatísticas de fluxo.
 */
void PrintFlowStats (FlowMonitorHelper &flowmon, Ptr<FlowMonitor> monitor) {
  monitor->CheckForLostPackets ();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i) {
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
    std::cout << std::endl << "Fluxo " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
    std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
    std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
    std::cout << "  Lost Packets: " << i->second.lostPackets << "\n";
    std::cout << "  Packet Loss Ratio: " << (double)i->second.lostPackets / i->second.txPackets << "\n";
    std::cout << "  Average Packet Size: " << (double)i->second.txBytes / i->second.txPackets << " bytes\n";
    std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / SIMULATION_TIME / 1000 / 1000  << " Mbps\n";
    std::cout << "  Delay: " << i->second.delaySum.GetSeconds() / i->second.rxPackets << " s\n";
    std::cout << "  Jitter: " << i->second.jitterSum.GetSeconds() / (i->second.rxPackets - 1) << " s\n";
  }
}

/**
 * Configura um link de rede entre dois nós e atualiza o mapa de interfaces.
 * @param node1 Primeiro nó do link.
 * @param node2 Segundo nó do link.
 * @param ndc Contêiner do dispositivo de rede para o link.
 * @param ipv4 Auxiliar de endereço IPv4 para atribuir endereços IP aos nós.
 * @param networkBase A base do endereço de rede para o link.
 */
void ConfigureNetworkLink(Ptr<Node> node1, Ptr<Node> node2, NetDeviceContainer ndc, Ipv4AddressHelper &ipv4, std::string networkBase) {
  // Verifica se os nós e o contêiner do dispositivo de rede são válidos
  if (node1 == nullptr || node2 == nullptr || ndc.GetN() == 0) {
    NS_LOG_ERROR("Nó inválido ou contêiner de dispositivo de rede vazio.");
    return;
  }
  // Configura a base do endereço de rede
  ipv4.SetBase(Ipv4Address(networkBase.c_str()), Ipv4Mask("255.255.255.0"));
  // Atribui endereços IP aos dispositivos de rede
  Ipv4InterfaceContainer iic = ipv4.Assign(ndc);
  // Atualiza o mapa de interfaces com as interfaces dos nós
  nodeInterfaceMap[{node1, node2}] = iic.Get(0).first->GetInterfaceForDevice(ndc.Get(0));
  nodeInterfaceMap[{node2, node1}] = iic.Get(1).first->GetInterfaceForDevice(ndc.Get(1));
}

/**
 * Função principal.
 */
int main(int argc, char *argv[]) {
  // LogComponentEnable("TopologySimulation", LOG_LEVEL_INFO);
  // LogComponentEnable("UdpClient", LOG_LEVEL_INFO);
  // LogComponentEnable("UdpServer", LOG_LEVEL_INFO);

  std::string routingProtocol = "rip";

  std::string subfolder = ".";

  CommandLine cmd;
  cmd.AddValue ("routingProtocol", "Protocolo de roteamento (rip ou olsr)", routingProtocol);
  cmd.AddValue ("subfolder", "Subpasta para os arquivos de saída", subfolder);
  cmd.Parse (argc, argv);

  std::string fileName = subfolder + "/topologia2_" + routingProtocol;

  // ==============================================================================================
  NS_LOG_INFO("** Criando nós da rede...");
  Ptr<Node> t = CreateNode ("T");
  Ptr<Node> r1 = CreateNode ("Router1");
  Ptr<Node> r2 = CreateNode ("Router2");
  Ptr<Node> r3 = CreateNode ("Router3");
  Ptr<Node> r4 = CreateNode ("Router4");
  Ptr<Node> r = CreateNode ("R");

  NodeContainer net1 (t, r1);  //          T -> Roteador_1
  NodeContainer net2 (r1, r2); // Roteador_1 -> Roteador_2
  NodeContainer net3 (r2, r);  // Roteador_2 -> R

  NodeContainer net4 (t, r3);  //          T -> Roteador_3
  NodeContainer net5 (r3, r4); // Roteador_3 -> Roteador_4
  NodeContainer net6 (r4, r);  // Roteador_3 -> R

  NodeContainer net7 (r1, r4); // Roteador_1 -> Roteador_4
  NodeContainer net8 (r3, r2); // Roteador_3 -> Roteador_2

  NodeContainer routers (r1, r2, r3, r4);
  NodeContainer nodes (t, r);

  // ==============================================================================================
  NS_LOG_INFO("** Criando canais de comunicação...");
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", DataRateValue(5000000)); // 5 Mbps
  p2p.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
  NetDeviceContainer ndc1 = p2p.Install(net1);
  NetDeviceContainer ndc2 = p2p.Install(net2);
  nodeInterfaceMap[{net2.Get(0), net2.Get(1)}] = ndc2.Get(0)->GetIfIndex();
  nodeInterfaceMap[{net2.Get(1), net2.Get(0)}] = ndc2.Get(1)->GetIfIndex();
  NetDeviceContainer ndc3 = p2p.Install(net3);
  NetDeviceContainer ndc4 = p2p.Install(net4);
  NetDeviceContainer ndc5 = p2p.Install(net5);
  NetDeviceContainer ndc6 = p2p.Install(net6);
  p2p.SetDeviceAttribute("DataRate", DataRateValue(2500000)); // 2.5 Mbps
  p2p.SetChannelAttribute("Delay", TimeValue(MilliSeconds(4)));
  NetDeviceContainer ndc7 = p2p.Install(net7);
  NetDeviceContainer ndc8 = p2p.Install(net8);

  // ==============================================================================================
  NS_LOG_INFO("** Instalando pilha de protocolos de internet IPv4 e roteamento...");
  InternetStackHelper internet;
  internet.SetIpv6StackInstall (false);

  if (routingProtocol == "rip") {
    RipHelper ripRouting;
    internet.SetRoutingHelper (ripRouting);
  } else if (routingProtocol == "olsr") {
    OlsrHelper olsrRouting;
    internet.SetRoutingHelper (olsrRouting);
  } else {
    NS_LOG_ERROR("Protocolo de roteamento inválido.");
    return 1;
  }

  internet.Install (routers);
  internet.Install (nodes);

  // ==============================================================================================
  NS_LOG_INFO("** Atribuindo endereços IPv4...");
  Ipv4AddressHelper ipv4;
  ConfigureNetworkLink(net1.Get(0), net1.Get(1), ndc1, ipv4, "10.0.1.0");
  ConfigureNetworkLink(net2.Get(0), net2.Get(1), ndc2, ipv4, "10.0.2.0");
  ConfigureNetworkLink(net3.Get(0), net3.Get(1), ndc3, ipv4, "10.0.3.0");
  ConfigureNetworkLink(net4.Get(0), net4.Get(1), ndc4, ipv4, "10.0.4.0");
  ConfigureNetworkLink(net5.Get(0), net5.Get(1), ndc5, ipv4, "10.0.5.0");
  ConfigureNetworkLink(net6.Get(0), net6.Get(1), ndc6, ipv4, "10.0.6.0");
  ConfigureNetworkLink(net7.Get(0), net7.Get(1), ndc7, ipv4, "10.0.7.0");
  ConfigureNetworkLink(net8.Get(0), net8.Get(1), ndc8, ipv4, "10.0.8.0");

  // ==============================================================================================
  NS_LOG_INFO("** Criando aplicações de envio de pacotes UDP...");
  uint16_t udpPort = 9;

  UdpServerHelper server (udpPort);
  ApplicationContainer serverApps = server.Install (r);

  Ipv4Address receiverAddress = r->GetObject<Ipv4>()->GetAddress(1,0).GetLocal();
  UdpClientHelper client (receiverAddress, udpPort);
  client.SetAttribute ("Interval", TimeValue (Seconds (UDP_PACKET_INTERVAL)));
  client.SetAttribute ("PacketSize", UintegerValue (1024));
  client.SetAttribute ("MaxPackets", UintegerValue (UDP_MAX_PACKETS));
  ApplicationContainer clientApps = client.Install (t);
  clientApps.Start (Seconds (UDP_TRANSMISSION_TIME));

  // ==============================================================================================
  // Configura a animação da simulação
  AnimationInterface::SetConstantPosition (t, 10.0, 50.0);
  AnimationInterface::SetConstantPosition (r1, 25.0, 25.0);
  AnimationInterface::SetConstantPosition (r2, 50.0, 25.0);
  AnimationInterface::SetConstantPosition (r3, 25.0, 75.0);
  AnimationInterface::SetConstantPosition (r4, 50.0, 75.0);
  AnimationInterface::SetConstantPosition (r, 90.0, 50.0);
  AnimationInterface anim (fileName + ".xml");
  anim.UpdateNodeDescription (t->GetId(), "Transmissor");
  anim.UpdateNodeSize (t->GetId(), 2.0, 2.0);
  anim.UpdateNodeColor (t->GetId(), 255, 255, 0);
  anim.UpdateNodeDescription (r1->GetId(), "Roteador 1");
  anim.UpdateNodeDescription (r2->GetId(), "Roteador 2");
  anim.UpdateNodeDescription (r3->GetId(), "Roteador 3");
  anim.UpdateNodeDescription (r4->GetId(), "Roteador 4");
  anim.UpdateNodeDescription (r->GetId(), "Receptor");
  anim.UpdateNodeSize (r->GetId(), 2.0, 2.0);
  anim.UpdateNodeColor (r->GetId(), 255, 255, 0);

  // ==============================================================================================
  // Simula a queda e subida dos enlaces Roteador_1 -> Roteador_2 e Roteador_3 -> Roteador_4
  Simulator::Schedule (Seconds (LINK_DOWN_TIME), &TearDownLink, r3, r2);
  Simulator::Schedule (Seconds (LINK_UP_TIME), &UpLink, r3, r2);

  // ==============================================================================================
  // Configura o monitoramento da rede
  AsciiTraceHelper ascii;
  p2p.EnableAsciiAll (ascii.CreateFileStream (fileName + ".tr"));
  p2p.EnablePcapAll (fileName, false);
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.Install(nodes);
  Ptr<NetworkConvergenceTracker> networkTracker = Create<NetworkConvergenceTracker> (routers);
  // Para o monitoramento da convergência da rede antes da queda do enlace a fim de evitar falsos positivos
  Simulator::Schedule (Seconds (LINK_DOWN_TIME), &NetworkConvergenceTracker::StopTracking, networkTracker);

  // ==============================================================================================
  NS_LOG_INFO("** Executando simulação...");
  Simulator::Stop (Seconds (SIMULATION_TIME));
  Simulator::Run();

  std::cout << "Tempo de convergência da rede: " << networkTracker->GetNetworkConvergenceTime().GetSeconds() << " s\n";
  PrintFlowStats (flowmon, monitor);

  Simulator::Destroy();
  NS_LOG_INFO("** Simulação finalizada.");

  return 0;
}