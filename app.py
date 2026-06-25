import gradio as gr
import requests
import os
from concurrent.futures import ThreadPoolExecutor

FEEDS_CTI = {
    "Proofpoint (Emerging Threats)": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Blocklist.de (Ataques Recentes)": "https://lists.blocklist.de/lists/all.txt",
    "Tor Exit Nodes (Nós de Saída)": "https://check.torproject.org/exit-addresses"
}

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
            return {
                "ip": ip,
                "score": dados.get('abuseConfidenceScore', 0),
                "pais": dados.get('countryCode', 'UN'),
                "isp": dados.get('isp', 'Desconhecido')
            }
    except Exception:
        pass
    return {"ip": ip, "erro": "Falha na consulta OSINT"}

def disparar_alerta_slack(logs_consolidacao, total_ips, alvos_criticos):
    """Envia o relatório de ameaças estruturado para o Slack."""
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return "⚠️ Alerta do Slack não configurado: URL do Webhook ausente."

    # Formatação de texto rica padrão do Slack (Markdown simplificado)
    texto_mensagem = (
        "🟢 *SENTINELA SOC - THREAT INTEL v4.0*\n"
        "_Pipeline de automação executado com sucesso no Hugging Face._\n\n"
        f"🔥 *Total de IPs Únicos Isolados:* `{total_ips}`\n\n"
        "*📊 Resumo da Varredura:*\n"
    )
    for log in logs_consolidacao:
        texto_mensagem += f"• {log}\n"
        
    texto_mensagem += "\n*🚨 Amostra Crítica Triada (OSINT):*\n"
    for c in alvos_criticos:
        if "erro" in c:
            continue
        emoji = "🔴" if c['score'] > 50 else "🟡"
        texto_mensagem += f"{emoji} `{c['ip']}` ({c['score']}% abuso) | Pais: {c['pais']} | ISP: _{c['isp']}_\n"

    payload = {"text": texto_mensagem}
    headers = {"Content-Type": "application/json"}

    try:
        resposta = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
        if resposta.status_code == 200:
            return "📢 Alerta enviado com sucesso para o Slack!"
        else:
            return f"❌ Slack rejeitou o envio. Status: {resposta.status_code}"
    except Exception as e:
        return f"❌ Falha de rede com a API do Slack: {str(e)}"

def agregar_e_enriquecer():
    ips_totais = set()
    logs_consolidacao = []
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        futuros = [executor.submit(requisitar_feed, nome, url) for nome, url in FEEDS_CTI.items()]
        for futuro in futuros:
            nome_feed, linhas = futuro.result()
            ips_do_feed = 0
            for linha in linhas: # Se der erro em lines anterior troque para linhas
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
            
    # Chamada para o motor do Slack
    status_envio = disparar_alerta_slack(logs_consolidacao, len(lista_final), resultados_osint)
            
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
    
    return resultado

theme_base = gr.themes.Default()

with gr.Blocks(theme=theme_base, css="style.css", title="SEK - SOC Operations Room") as interface:
    with gr.Row():
        gr.Markdown("💻 **SEC Threat Intelligence System v4.0** | Console com Alerta Slack")
    
    with gr.Row():
        with gr.Column(scale=1, elem_classes=["cyber-box"]):
            gr.Markdown("### 🎛️ PIPELINE CORPORATIVO")
            gr.Markdown("Execução integrada de Threat Intelligence com alerta automatizado via Slack.")
            btn_disparar = gr.Button("Iniciar Pipeline", elem_classes=["neon-btn"])
            gr.Markdown("📊 **Engine Specs:**\n* ThreadPool: Active\n* Slack Hook: Connected\n* Auto-Dedup: Enabled")
            
        with gr.Column(scale=2):
            output_log = gr.Textbox(
                label="MONITOR DE EXECUÇÃO / OUTPUT LOG", 
                lines=22,
                placeholder="Aguardando início manual pela interface...",
                elem_classes=["terminal-console"]
            )
            
    btn_disparar.click(fn=agregar_e_enriquecer, inputs=None, outputs=output_log)

if __name__ == "__main__":
    interface.launch()
