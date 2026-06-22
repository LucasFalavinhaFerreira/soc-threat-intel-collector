# 🛡️ SOC Threat Intelligence - Automated IoC Collector

Um extrator automatizado de Indicadores de Comprometimento (IoCs) voltado para operações de SOC (Security Operations Center) e Threat Intelligence. A aplicação realiza o web scraping dinâmico de feeds globais de reputação e ameaças, estruturando listas de IPs comprometidos ativos para alimentação de Firewalls, SIEMs ou ferramentas de detecção (SOAR).

## 🚀 Tecnologias Utilizadas
* **Python 3.13**
* **Requests** para requisições HTTP e extração de feeds de CTI.
* **Gradio 6** para interface de usuário rápida e interativa.
* **Hugging Face Spaces** para hospedagem do contêiner da aplicação.

## 🛠️ Como rodar localmente

1. Clone o repositório:
```bash
git clone <seu-link-do-github>
Instale as dependências listadas no requirements.txt:

Bash
pip install -r requirements.txt
Execute o script principal:

Bash
python app.py
```
*(Lembrando que no seu `requirements.txt` ficam apenas as linhas `requests` e `gradio`).*

## 📈 Histórico de Desenvolvimento & Debug (Changelog)

* **v1.0.0 (Base Alpha):** Desenvolvimento da estrutura inicial voltada para o feed do Feodo Tracker (Abuse.ch). 
* **v1.1.0 (Hotfix - Tratamento de Erro 404):** Identificada descontinuação do diretório de texto puro por parte do feed antigo. Migração da inteligência de ameaças para o ecossistema global **Emerging Threats (Proofpoint)**, adicionando cabeçalhos de `User-Agent` para contornar bloqueios anti-scraping de requisições automatizadas nuas.
* **v1.2.0 (Bugfix - Loop de Variáveis):** Correção crítica no interpretador Python onde um erro de nomenclatura de variável (`lines` vs `linhas`) causava falha na indexação dos dados coletados. Após o ajuste, o pipeline passou a extrair com sucesso mais de 600 IoCs ativos em tempo real por requisição.
