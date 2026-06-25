import gradio as gr
import requests
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

FEEDS_CTI = {
    "Proofpoint (Emerging Threats)": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Blocklist.de (Ataques Recentes)": "https://lists.blocklist.de/lists/all.txt",
    "Tor Exit Nodes (Nós de Saída)": "https://check.torproject.org/exit-addresses"
}

DB_FILE = "threat_intel.db"

def inicializar_banco():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historico_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            data_registro TEXT,
            score INTEGER,
            pais TEXT,
            isp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def salvar_no_banco(ip, score, pais, isp):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO historico_ips (ip, data_registro, score, pais, isp)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, data_atual, score, pais, isp))
        conn.commit()
        conn.close()
    except Exception:
        pass

def obter_metricas_banco():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM historico_ips")
        total_historico = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT pais, COUNT(*) as qtd 
            FROM historico_ips 
            GROUP BY pais 
            ORDER BY qtd DESC 
            LIMIT 5
        ''')
        top_paises = cursor.fetchall()
        conn.close()
        
        if total_historico == 0:
            return "Banco de dados ainda vazio. Execute a primeira análise."
            
        texto_metricas = f"Registos Totais no Banco: {total_historico}\n\n"
        texto_metricas += "Top 5 Países Recorrentes:\n"
        for p in top_paises:
            texto_metricas += f"• {p[0]}: {p[1]} ocorrências\n"
        return texto_metricas
    except Exception as e:
        return f"Erro ao ler métricas do banco: {str(e)}"

def requisitar_feed(nome_feed, url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        resposta = requests.get(url, headers=headers, timeout=8)
        if resposta.status_code == 200:
            return nome_feed, resposta.text.split("\n")
    except Exception:
        pass
    return nome_feed, []

def enriquecer_ip(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"ip": ip, "erro": "API KEY Ausente"}
        
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    
    try:
        resposta = requests.get(url, headers=headers, params=querystring, timeout=5)
        if resposta.status_code == 200:
            dados = resposta.json()['data']
            res = {
                "ip": ip,
                "score": dados.get('abuseConfidenceScore', 0),
                "pais": dados.get('countryCode', 'UN'),
                "isp": dados.get('isp', 'Desconhecido')
            }
            salvar_no_banco(res['ip'], res['score'], res['pais'], res['isp'])
            return res
    except Exception:
        pass
    return {"ip": ip, "erro": "Falha na consulta OSINT"}

def disparar_alerta_slack(logs_consolidacao, total_ips, alvos_criticos):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return "Alerta do Slack não configurado: URL do Webhook ausente."

    texto_mensagem = (
        "🟢 SENTINELA SOC - THREAT INTEL v5.0\n"
        "Pipeline de automação executado com sucesso no Hugging Face.\n\n"
        f"🔥 Total de IPs Únicos Isolados: {total_ips}\n\n"
        "📊 Resumo da Varredura:\n"
    )
    for log in logs_consolidacao:
        texto_mensagem += f"• {log}\n"
        
    texto_mensagem += "\n🚨 Amostra Crítica Triada (OSINT) e Salva no Banco:\n"
    for c in alvos_criticos:
        if "erro" in c:
            continue
        emoji = "🔴" if c['score'] > 50 else "🟡"
        texto_mensagem += f"{emoji} {c['ip']} ({c['score']}% abuso) | Pais: {c['pais']} | ISP: {c['isp']}\n"

    payload = {"text": texto_mensagem}
    headers = {"Content-Type": "application/json"}

    try:
        resposta = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
        if resposta.status_code == 200:
            return "Alerta enviado com sucesso para o Slack!"
        else:
            return f"Slack rejeitou o envio. Status: {resposta.status_code}"
    except Exception as e:
        return f"Falha de rede com a API do Slack: {str(e)}"

# Nova função dedicada para gerar a lista em texto puro via API externa
def api_retornar_lista_bruta():
    ips_totais = set()
    with ThreadPoolExecutor(max_workers=3) as executor:
        futuros = [executor.submit(requisitar_feed, nome, url) for nome, url in FEEDS_CTI.items()]
        for futuro in futuros:
            nome_feed, linhas = futuro.result()
            for linha in linhas:
                linha = linha.strip()
                if not linha or linha.startswith("#"):
                    continue
                if nome_feed == "Tor Exit Nodes (Nós de Saída)":
                    if linha.startswith("ExitAddress"):
                        ips_totais.add(linha.split()[1])
                else:
                    if not linha.isalpha() and "." in linha:
                        ips_totais.add(linha)
    
    lista_final = sorted(list(ips_totais))
    # Une os mais de 22 mil IPs pulando linha para o firewall ler como bloco de texto
    return "\n".join(lista_final)

def agregar_e_enriquecer():
    ips_totais = set()
    logs_consolidacao = []
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        futuros = [executor.submit(requisitar_feed, nome, url) for nome, url in FEEDS_CTI.items()]
        for futuro in futuros:
            nome_feed, linhas = futuro.result()
            ips_do_feed = 0
            for linha in linhas:
                linha = linha.strip()
                if not linha or linha.startswith("#"):
                    continue
                if nome_feed == "Tor Exit Nodes (Nós de Saída)":
                    if linha.startswith("ExitAddress"):
                        ips_totais.add(linha.split()[1])
                        ips_do_feed += 1
                else:
                    if not linha.isalpha() and "." in linha:
                        ips_totais.add(linha)
                        ips_do_feed += 1
            logs_consolidacao.append(f"✔️ {nome_feed}: {ips_do_feed} IPs.")

    lista_final = sorted(list(ips_totais))
    ips_para_analise = lista_final[:5]
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        resultados_osint = list(executor.map(enriquecer_ip, ips_para_analise))
            
    status_envio = disparar_alerta_slack(logs_consolidacao, len(lista_final), resultados_osint)
    metricas_atualizadas = obter_metricas_banco()
            
    resultado = f"--- STATUS DO DISPARO: {status_envio} ---\n\n"
    resultado += "--- STATUS DA CONSOLIDAÇÃO MULTILISTA ---\n"
    resultado += "\n".join(logs_consolidacao) + "\n"
    resultado += f"\n🔥 Total de IPs Únicos na Blocklist Global: {len(lista_final)}\n"
    separador = "-----------------------------------------\n\n"
    resultado += separador
    
    resultado += "🚨 ENRIQUECIMENTO OSINT EM TEMPO REAL (Amostra de Críticos):\n"
    for c in resultados_osint:
        if "erro" in c:
            resultado += f"⚠️ {c['ip']} | {c['erro']}\n"
        else:
            status = "🔴 CRÍTICO" if c['score'] > 50 else "🟡 SUSPEITO"
            resultado += f"🛡️ {c['ip']} -> Veredito: {status} ({c['score']}% abuso) | País: {c['pais']} | ISP: {c['isp']}\n"
            
    resultado += "\n" + separador
    resultado += "📦 LISTA COMPLETA DE IPs PARA BLOCKLIST:\n"
    resultado += "\n".join(lista_final)
    
    return resultado, metricas_atualizadas

inicializar_banco()

theme_base = gr.themes.Default()

# CORREÇÃO GRADIO 6: theme, css e title foram movidos para o launch()
with gr.Blocks() as interface:
    gr.Markdown("💻 SEC Threat Intelligence System v5.0 | Console com Persistência SQLite")
    
    with gr.Row():
        with gr.Column(scale=1, elem_classes=["cyber-box"]):
            gr.Markdown("### 🎛️ PIPELINE CORPORATIVO")
            gr.Markdown("Execução integrada de Threat Intelligence com armazenamento local e alertas.")
            btn_disparar = gr.Button("Iniciar Pipeline", elem_classes=["neon-btn"])
            
            gr.Markdown("---")
            gr.Markdown("### 📈 MÉTRICAS DO BANCO")
            output_banco = gr.Textbox(
                label="Estatísticas Acumuladas",
                value=obter_metricas_banco(),
                lines=5,
                interactive=False
            )
            
            gr.Markdown("---")
            gr.Markdown("### 📦 EXPORTAR DADOS")
            btn_baixar_db = gr.Button("Gerar Arquivo do Banco", size="sm")
            componente_download = gr.File(label="Download do Banco SQLite", interactive=False)
            
            gr.Markdown("📊 Engine Specs:\n* ThreadPool: Active\n* SQLite3: Connected\n* Slack Hook: Connected\n* API Endpoint: Ready")
            
        with gr.Column(scale=2):
            output_log = gr.Textbox(
                label="MONITOR DE EXECUÇÃO / OUTPUT LOG", 
                lines=22,
                placeholder="Aguardando início manual pela interface...",
                elem_classes=["terminal-console"]
            )
            
    btn_disparar.click(
        fn=agregar_e_enriquecer, 
        inputs=None, 
        outputs=[output_log, output_banco]
    )
    
    btn_baixar_db.click(
        fn=lambda: DB_FILE if os.path.exists(DB_FILE) else None,
        inputs=None,
        outputs=componente_download
    )

if __name__ == "__main__":
    interface.queue()
    # Removido o show_api que estava quebrando o contêiner
    interface.launch(
        theme=theme_base,
        css="style.css"
    )
