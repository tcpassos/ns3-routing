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
#include "ns3/csma-module.h"
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
#define UDP_MAX_PACKETS 10000
#define LINK_DOWN_TIME 100.0
#define LINK_UP_TIME 200.0

NS_LOG_COMPONENT_DEFINE("TopologySimulation");

/**
 * Classe para monitorar a tabela de roteamento de um nó.
 */
class RoutingTableTracker : public Object {
public:
  RoutingTableTracker (Ptr<Node> node) : m_tracking(false), m_node (node) { }

  void Start () {
    m_tracking = true;
    m_lastChangeTime = Simulator::Now();
    m_lastRoutingTable = GetRoutingTable ();
    Simulator::Schedule (Seconds (1.0), &RoutingTableTracker::CheckRoutingTable, this);
  }

  void Stop () {
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

  void Start () {
    m_startTime = Simulator::Now();
    for (const auto& tracker : m_trackers) {
      tracker->Start();
    }
  }

  void Stop () {
    for (const auto& tracker : m_trackers) {
      tracker->Stop();
    }
  }

  Time GetNetworkConvergenceTime () const {
    Time maxTime = Seconds (0);
    for (const auto& tracker : m_trackers) {
      auto convergenceTime = tracker->GetLastChangeTime ();
      if (convergenceTime > maxTime) {
        maxTime = convergenceTime;
      }
    }
    return maxTime - m_startTime;
  }

private:
  std::vector<Ptr<RoutingTableTracker>> m_trackers;
  Time m_startTime;
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
 * Desabilita um enlace entre dois nós de uma rede.
 *
 * @param devices Dispositivos de rede conectados.
 */
void TearDownLink(NetDeviceContainer devices) {
  Ptr<NetDevice> device1 = devices.Get(0);
  Ptr<NetDevice> device2 = devices.Get(1);
  Ptr<Ipv4> ipv4Device1 = device1->GetNode()->GetObject<Ipv4>();
  Ptr<Ipv4> ipv4Device2 = device2->GetNode()->GetObject<Ipv4>();
  uint32_t interface1 = ipv4Device1->GetInterfaceForDevice(device1);
  uint32_t interface2 = ipv4Device2->GetInterfaceForDevice(device2);
  ipv4Device1->SetDown(interface1);
  ipv4Device2->SetDown(interface2);
}

/**
 * Imprime as interfaces de rede.
 *
 * @param devices Dispositivos de rede conectados.
 */
void UpLink(NetDeviceContainer devices) {
  Ptr<NetDevice> device1 = devices.Get(0);
  Ptr<NetDevice> device2 = devices.Get(1);
  Ptr<Ipv4> ipv4Device1 = device1->GetNode()->GetObject<Ipv4>();
  Ptr<Ipv4> ipv4Device2 = device2->GetNode()->GetObject<Ipv4>();
  uint32_t interface1 = ipv4Device1->GetInterfaceForDevice(device1);
  uint32_t interface2 = ipv4Device2->GetInterfaceForDevice(device2);
  ipv4Device1->SetUp(interface1);
  ipv4Device2->SetUp(interface2);
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
 * Função principal.
 */
int main(int argc, char *argv[]) {
  // LogComponentEnable("TopologySimulation", LOG_LEVEL_INFO);

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

  NodeContainer netTR1(t, r1);
  NodeContainer netTR3(t, r3);
  NodeContainer netR1R2(r1, r2);
  NodeContainer netR1R4(r1, r4);
  NodeContainer netR3R4(r3, r4);
  NodeContainer netR3R2(r3, r2);
  NodeContainer netR2R(r2, r);
  NodeContainer netR4R(r4, r);

  NodeContainer routers (r1, r2, r3, r4);
  NodeContainer nodes (t, r);

  // ==============================================================================================
  NS_LOG_INFO("** Configurando pilha de protocolos de internet IPv4 e roteamento...");
  InternetStackHelper internet;

  if (routingProtocol == "rip") {
    RipHelper ripHelper;
    // Peso 2
    ripHelper.SetInterfaceMetric(r1, 3, 2); // R1 -> R4
    ripHelper.SetInterfaceMetric(r4, 3, 2);
    ripHelper.SetInterfaceMetric(r3, 3, 2); // R3 -> R2
    ripHelper.SetInterfaceMetric(r2, 3, 2);
    internet.SetRoutingHelper (ripHelper);
  } else if (routingProtocol == "olsr") {
    OlsrHelper olsrHelper;
    internet.SetRoutingHelper (olsrHelper);
  } else {
    NS_LOG_ERROR("Protocolo de roteamento inválido.");
    return 1;
  }

  internet.Install (NodeContainer(nodes, routers));

  // ==============================================================================================
  NS_LOG_INFO("** Atribuindo endereços IPv4...");
  Ipv4AddressHelper ipv4;
  CsmaHelper csma;

  csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
  csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));
  
  ipv4.SetBase(Ipv4Address("10.0.0.0"), "255.255.255.0");
  NetDeviceContainer ndcTR1 = csma.Install(netTR1);
  ipv4.Assign(ndcTR1);

  NetDeviceContainer ndcR1R2 = csma.Install(netR1R2);
  ipv4.SetBase(Ipv4Address("10.0.1.0"), "255.255.255.0");
  ipv4.Assign(ndcR1R2);

  NetDeviceContainer ndcR2R = csma.Install(netR2R);
  ipv4.SetBase(Ipv4Address("10.0.2.0"), "255.255.255.0");
  ipv4.Assign(ndcR2R);

  NetDeviceContainer ndcTR3 = csma.Install(netTR3);
  ipv4.SetBase(Ipv4Address("10.0.3.0"), "255.255.255.0");
  ipv4.Assign(ndcTR3);

  NetDeviceContainer ndcR3R4 = csma.Install(netR3R4);
  ipv4.SetBase(Ipv4Address("10.0.4.0"), "255.255.255.0");
  ipv4.Assign(ndcR3R4);

  NetDeviceContainer ndcR4R = csma.Install(netR4R);
  ipv4.SetBase(Ipv4Address("10.0.5.0"), "255.255.255.0");
  ipv4.Assign(ndcR4R);

  // Redes com enlaces de peso 2
  // Como não é possível definir a métrica para o protocolo OLSR, afetamos a taxa de transmissão
  csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("5Mbps")));
  csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(13120)));

  NetDeviceContainer ndcR1R4 = csma.Install(netR1R4);
  ipv4.SetBase(Ipv4Address("10.0.6.0"), "255.255.255.0");
  ipv4.Assign(ndcR1R4);

  NetDeviceContainer ndcR3R2 = csma.Install(netR3R2);
  ipv4.SetBase(Ipv4Address("10.0.7.0"), "255.255.255.0");
  ipv4.Assign(ndcR3R2);
  
  // ==============================================================================================
  // Tabela com a relação de interfaces e nós
  // T-1 -> 1-Router1
  // T-2 -> 1-Router3
  // Router1-1 -> 1-T
  // Router1-2 -> 1-Router2
  // Router1-3 -> 3-Router4
  // Router2-1 -> 1-Router1
  // Router2-2 -> 1-R
  // Router2-3 -> 3-Router3
  // Router3-1 -> 2-T
  // Router3-2 -> 1-Router4
  // Router3-3 -> 3-Router2
  // Router4-1 -> 2-Router3
  // Router4-2 -> 2-R
  // Router4-3 -> 3-Router1
  // R-1 -> 2-Router2
  // R-2 -> 2-Router4

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
  Simulator::Schedule (Seconds (LINK_DOWN_TIME), &TearDownLink, ndcR1R2);
  Simulator::Schedule (Seconds (LINK_UP_TIME), &UpLink, ndcR1R2);
  Simulator::Schedule (Seconds (LINK_DOWN_TIME), &TearDownLink, ndcR3R4);
  Simulator::Schedule (Seconds (LINK_UP_TIME), &UpLink, ndcR3R4);

  // ==============================================================================================
  // Configura o monitoramento da rede
  csma.EnablePcapAll (fileName, false);
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.Install(nodes);

  Ptr<NetworkConvergenceTracker> convergenceBeforeDown = Create<NetworkConvergenceTracker> (routers);
  Simulator::Schedule (Seconds (0.0), &NetworkConvergenceTracker::Start, convergenceBeforeDown);
  Simulator::Schedule (Seconds (LINK_DOWN_TIME), &NetworkConvergenceTracker::Stop, convergenceBeforeDown);

  Ptr<NetworkConvergenceTracker> convergenceDuringDown = Create<NetworkConvergenceTracker> (routers);
  Simulator::Schedule (Seconds (LINK_DOWN_TIME), &NetworkConvergenceTracker::Start, convergenceDuringDown);
  Simulator::Schedule (Seconds (LINK_UP_TIME), &NetworkConvergenceTracker::Stop, convergenceDuringDown);

  Ptr<NetworkConvergenceTracker> convergenceAfterDown = Create<NetworkConvergenceTracker> (routers);
  Simulator::Schedule (Seconds (LINK_UP_TIME), &NetworkConvergenceTracker::Start, convergenceAfterDown);
  Simulator::Schedule (Seconds (SIMULATION_TIME), &NetworkConvergenceTracker::Stop, convergenceAfterDown);

  // ==============================================================================================
  NS_LOG_INFO("** Executando simulação...");
  Simulator::Stop (Seconds (SIMULATION_TIME));
  Simulator::Run();

  std::cout << "Convergência antes da queda do enlace: " << convergenceBeforeDown->GetNetworkConvergenceTime().GetSeconds() << " s\n";
  std::cout << "Convergência durante a queda do enlace: " << convergenceDuringDown->GetNetworkConvergenceTime().GetSeconds() << " s\n";
  std::cout << "Convergência após a queda do enlace: " << convergenceAfterDown->GetNetworkConvergenceTime().GetSeconds() << " s\n";
  PrintFlowStats (flowmon, monitor);

  Simulator::Destroy();
  NS_LOG_INFO("** Simulação finalizada.");

  return 0;
}