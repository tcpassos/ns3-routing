//    Topologia da rede:
//
//                +---------------------------x------------------------+
//                |                                                    |
//   (T) ---> (Roteador_1) ---> (Roteador_2) --> (Roteador_3) --> (Roteador_4) --> (R)
//                |                                     /
//                +------------------------------------+
//
//                Todos os enlaces possuem peso 1, exceto os enlaces entre Roteador_1 e Roteador_3 que tem peso 3
//                                                                 e entre Roteador_1 e Roteador_4 que tem peso 4.
//
// Após o LINK_DOWN_TIME, o enlace entre o Roteador_1 e o Roteador_4 é derrubado.
// Após o LINK_UP_TIME, os enlaces são restaurados.
//
//
// Para rodar a simulação com ambos os protocolos de roteamento, execute:
// (Criar a pasta "resultados" antes de executar o comando)
// ./waf --run "topologia3 --routingProtocol=rip --subfolder=resultados" && ./waf --run "topologia3 --routingProtocol=olsr --subfolder=resultados"
//
// Essa simulação irá gerar arquivos PCAP para cada enlace da rede, que podem ser visualizados com o Wireshark.
// Para mesclar os arquivos PCAP em um único arquivo, execute o comando dentro da pasta onde os arquivos estão:
// mergecap -w topologia3_rip.pcap $(find . -type f -regex "./topologia3_rip.*\.pcap$")
// mergecap -w topologia3_olsr.pcap $(find . -type f -regex "./topologia3_olsr.*\.pcap$")
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
void PrintFlowStats(FlowMonitorHelper* flowmonHelper, Ptr<FlowMonitor> monitor) {
  std::cout << "\n=== Estatísticas de fluxo totais aos " << Simulator::Now().GetSeconds() << " s ===\n";
  monitor->CheckForLostPackets();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper->GetClassifier());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

  uint32_t totalTxPackets = 0, totalRxPackets = 0, totalLostPackets = 0;
  uint64_t totalTxBytes = 0, totalRxBytes = 0;
  double totalDelaySum = 0, totalJitterSum = 0;
  int totalFlows = 0;

  for (const auto& stat : stats) {
    totalTxPackets += stat.second.txPackets;
    totalRxPackets += stat.second.rxPackets;
    totalLostPackets += stat.second.lostPackets;
    totalTxBytes += stat.second.txBytes;
    totalRxBytes += stat.second.rxBytes;
    totalDelaySum += stat.second.delaySum.GetSeconds();
    totalJitterSum += stat.second.rxPackets > 1 ? stat.second.jitterSum.GetSeconds() : 0;
    totalFlows++;
  }

  if (totalFlows > 0) {
    std::cout << "Total de Fluxos: " << totalFlows << "\n"
              << "Total Tx Packets: " << totalTxPackets << "\n"
              << "Total Rx Packets: " << totalRxPackets << "\n"
              << "Total Lost Packets: " << totalLostPackets << "\n"
              << "Packet Loss Ratio: " << (totalTxPackets ? static_cast<double>(totalLostPackets) / totalTxPackets : 0) << "\n"
              << "Average Packet Size: " << (totalTxPackets ? static_cast<double>(totalTxBytes) / totalTxPackets : 0) << " bytes\n"
              << "Throughput: " << totalRxBytes * 8.0 / SIMULATION_TIME / 1000 / 1000 << " Mbps\n"
              << "Average Delay: " << (totalRxPackets ? totalDelaySum / totalRxPackets : 0) << " s\n"
              << "Average Jitter: " << (totalRxPackets > 1 ? totalJitterSum / (totalRxPackets - 1) : 0) << " s\n";
  } else {
    std::cout << "Nenhum fluxo detectado.\n";
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

  std::string fileName = subfolder + "/topologia3_" + routingProtocol;

  // ==============================================================================================
  NS_LOG_INFO("** Criando nós da rede...");
  Ptr<Node> t = CreateNode ("T");
  Ptr<Node> r1 = CreateNode ("Router1");
  Ptr<Node> r2 = CreateNode ("Router2");
  Ptr<Node> r3 = CreateNode ("Router3");
  Ptr<Node> r4 = CreateNode ("Router4");
  Ptr<Node> r = CreateNode ("R");

  NodeContainer netTR1(t, r1);
  NodeContainer netR1R2(r1, r2);
  NodeContainer netR2R3(r2, r3);
  NodeContainer netR3R4(r3, r4);
  NodeContainer netR4R(r4, r);
  NodeContainer netR1R3(r1, r3);
  NodeContainer netR1R4(r1, r4);

  NodeContainer routers (r1, r2, r3, r4);
  NodeContainer nodes (t, r);

  // ==============================================================================================
  NS_LOG_INFO("** Configurando pilha de protocolos de internet IPv4 e roteamento...");
  InternetStackHelper internet;
  internet.SetIpv6StackInstall (false);

  if (routingProtocol == "rip") {
    RipHelper ripHelper;
    // R1 -> R4 Peso 3
    ripHelper.SetInterfaceMetric(r1, 4, 3);
    ripHelper.SetInterfaceMetric(r4, 3, 3);
    // R1 -> R3 Peso 4
    ripHelper.SetInterfaceMetric(r1, 3, 4);
    ripHelper.SetInterfaceMetric(r3, 3, 4);
    internet.SetRoutingHelper (ripHelper);
  } else if (routingProtocol == "olsr") {
    OlsrHelper olsrRouting;
    internet.SetRoutingHelper (olsrRouting);
  } else {
    NS_LOG_ERROR("Protocolo de roteamento inválido.");
    return 1;
  }

  internet.Install (NodeContainer(nodes, routers));

  // ==============================================================================================
  NS_LOG_INFO("** Atribuindo endereços IPv4...");
  Ipv4AddressHelper ipv4;
  CsmaHelper csma;

  // Peso 1
  csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
  csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));
  
  ipv4.SetBase(Ipv4Address("10.0.0.0"), "255.255.255.0");
  NetDeviceContainer ndcTR1 = csma.Install(netTR1);
  ipv4.Assign(ndcTR1);

  NetDeviceContainer ndcR1R2 = csma.Install(netR1R2);
  ipv4.SetBase(Ipv4Address("10.0.1.0"), "255.255.255.0");
  ipv4.Assign(ndcR1R2);

  NetDeviceContainer ndcR2R3 = csma.Install(netR2R3);
  ipv4.SetBase(Ipv4Address("10.0.2.0"), "255.255.255.0");
  ipv4.Assign(ndcR2R3);

  NetDeviceContainer ndcR3R4 = csma.Install(netR3R4);
  ipv4.SetBase(Ipv4Address("10.0.3.0"), "255.255.255.0");
  ipv4.Assign(ndcR3R4);

  NetDeviceContainer ndcR4R = csma.Install(netR4R);
  ipv4.SetBase(Ipv4Address("10.0.4.0"), "255.255.255.0");
  ipv4.Assign(ndcR4R);

  // Como não é possível definir a métrica para o protocolo OLSR, afetamos a taxa de transmissão
  
  // Redes com enlaces de peso 2
  csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(13120)));
  csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("5Mbps")));
  NetDeviceContainer ndcR1R3 = csma.Install(netR1R3);
  ipv4.SetBase(Ipv4Address("10.0.5.0"), "255.255.255.0");
  ipv4.Assign(ndcR1R3);

  csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("1Mbps")));
  NetDeviceContainer ndcR1R4 = csma.Install(netR1R4);
  ipv4.SetBase(Ipv4Address("10.0.6.0"), "255.255.255.0");
  ipv4.Assign(ndcR1R4);

  // ==============================================================================================
  // Tabela com a relação de interfaces e nós
  // R1-1 1-T
  // R1-2 1-R2
  // R1-3 3-R3
  // R1-4 3-R4
  // R2-1 1-R1
  // R2-2 1-R3
  // R3-1 2-R2
  // R3-2 1-R4
  // R3-3 3-R1
  // R4-1 2-R3
  // R4-2 1-R
  // R4-3 4-R1
  // R-1 2-R4

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
  AnimationInterface::SetConstantPosition (t, 25.0, 50.0);
  AnimationInterface::SetConstantPosition (r1, 40.0, 20.0);
  AnimationInterface::SetConstantPosition (r2, 40.0, 40.0);
  AnimationInterface::SetConstantPosition (r3, 50.0, 60.0);
  AnimationInterface::SetConstantPosition (r4, 70.0, 80.0);
  AnimationInterface::SetConstantPosition (r, 85.0, 50.0);
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
  // Simula a queda e subida do enlace Roteador_1 -> Roteador_4
  Simulator::Schedule (Seconds (LINK_DOWN_TIME), &TearDownLink, ndcR1R4);
  Simulator::Schedule (Seconds (LINK_UP_TIME), &UpLink, ndcR1R4);

  // ==============================================================================================
  // Configura o monitoramento da rede
  csma.EnablePcapAll (fileName, false);

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.Install(nodes);
  Simulator::Schedule (Seconds (LINK_DOWN_TIME), &PrintFlowStats, &flowmon, monitor);
  Simulator::Schedule (Seconds (LINK_UP_TIME), &PrintFlowStats, &flowmon, monitor);
  Simulator::Schedule (Seconds (SIMULATION_TIME), &PrintFlowStats, &flowmon, monitor);

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

  std::cout << std::endl << "Tempos de convergência do protocolo " << routingProtocol << ":\n";
  std::cout << "Antes da queda do enlace: " << convergenceBeforeDown->GetNetworkConvergenceTime().GetSeconds() << " s\n";
  std::cout << "Durante a queda do enlace: " << convergenceDuringDown->GetNetworkConvergenceTime().GetSeconds() << " s\n";
  std::cout << "Após a queda do enlace: " << convergenceAfterDown->GetNetworkConvergenceTime().GetSeconds() << " s\n";

  Simulator::Destroy();
  NS_LOG_INFO("** Simulação finalizada.");

  return 0;
}