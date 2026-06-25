# 🛡️ SOC Threat Intelligence - Agregador, OSINT, Persistência e API v5.0
Um ecossistema tático corporativo de Inteligência de Ameaças (Threat Intelligence) voltado para operações de SOC (Security Operations Center). A aplicação realiza a coleta paralela de múltiplos feeds globais, remove redundâncias, executa enriquecimento automatizado via API do AbuseIPDB, armazena o histórico em banco de dados local SQLite e expõe tanto notificações ativas via Slack quanto um endpoint de API para integração com Firewalls e ferramentas de rede.

Arquitetura e Engenharia do Projeto
Multi-source Scraping: Coleta simultânea dos feeds Proofpoint (Emerging Threats), Blocklist.de (brute force recente) e Tor Exit Nodes.

Paralelismo (Multithreading): Implantação de concurrent.futures.ThreadPoolExecutor para otimizar as requisições HTTP simultâneas de download.

Camada de Persistência (SQLite3): Armazenamento de IoCs triados com carimbo de data/hora, permitindo gerar estatísticas cumulativas e rankings de países atacantes diretamente na interface gráfica.

Alerta Ativo e Direcionado: Integração resiliente via Incoming Webhooks do Slack para despacho automático de relatórios táticos estruturados logo após a consolidação.

Barramento de API Integrado: Rota nativa exposta via Gradio que fornece a lista consolidada em formato de texto bruto, ideal para integração automática em Firewalls corporativos (como pfSense e OPNsense) ou scripts em PowerShell no Active Directory.

Interface Modular Segregada: Camada visual baseada em Gradio e folha de estilo customizada (style.css), garantindo a estética profissional de consoles de segurança.

Estrutura do Repositório
Plaintext
├── app.py           # Core do sistema, motor SQL, rotas de API e integrações
├── style.css        # Interface visual customizada (SOC Cyber Theme)
└── requirements.txt # Dependências do projeto (requests, gradio)
Histórico de Evolução do Projeto
v1.0.0: Script básico de extração estruturada de feed único.

v2.0.0 (Multithreading): Implementação de concorrência paralela e desduplicação multilista (escalabilidade para mais de 22 mil IoCs).

v3.0.0 (OSINT e UI Upgrade): Integração da API do AbuseIPDB e separação do design visual para um arquivo CSS dedicado.

v4.0.0 (Notificação Ativa): Transição do monitoramento manual para a notificação em tempo real via mensageria corporativa no Slack.

v5.0.0 (Persistência e API): Introdução do banco de dados SQLite para inteligência cumulativa e abertura do endpoint de API para automação de regras de Firewall.
