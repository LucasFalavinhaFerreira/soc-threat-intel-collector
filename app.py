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
        return f"❌ {ip} | [Erro: API KEY Ausente]"
        
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    
    try:
        resposta = requests.get(url, headers=headers, params=querystring, timeout=5)
        if resposta.status_code == 200:
            dados = resposta.json()['data']
            score = dados.get('abuseConfidenceScore', 0)
            pais = dados.get('countryCode', 'UN')
            isp = dados.get('isp', 'Desconhecido')
            
            status = "🔴 CRÍTICO" if score > 50 else "🟡 SUSPEITO"
            return f"🛡️ {ip} -> Veredito: {status} ({score}% abuso) | País: {pais} | ISP: {isp}"
    except Exception:
        pass
    return f"⚠️ {ip} | Falha na consulta OSINT."

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
                    # CORRIGIDO: Removido o acento de 'linha' que causava o crash
                    if not linha.isalpha() and "." in linha:
                        ips_totais.add(linha)
                        ips_do_feed += 1
            logs_consolidacao.append(f"✔️ {nome_feed}: {ips_do_feed} IPs processados.")

    lista_final = sorted(list(ips_totais))
    ips_para_analise = lista_final[:5]
    enriquecidos = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        resultados_osint = executor.map(enriquecer_ip, ips_para_analise)
        for res in resultados_osint:
            enriquecidos.append(res)
            
    resultado = "--- STATUS DA CONSOLIDAÇÃO MULTILISTA ---\n"
    resultado += "\n".join(logs_consolidacao) + "\n"
    resultado += f"\n🔥 Total de IPs Únicos na Blocklist Global: {len(lista_final)}\n"
    resultado += "-----------------------------------------\n\n"
    resultado += "🚨 ENRIQUECIMENTO OSINT EM TEMPO REAL (Amostra de Críticos):\n"
    resultado += "\n".join(enriquecidos) + "\n"
    resultado += "-----------------------------------------\n\n"
    resultado += "📦 LISTA COMPLETA DE IPs PARA BLOCKLIST:\n"
    resultado += "\n".join(lista_final)
    
    return resultado

# Instancia o tema escuro padrão do Gradio (sem poluição visual)
theme_base = gr.themes.Default()

# Monta a UI apontando explicitamente para o arquivo 'style.css' externo
with gr.Blocks(theme=theme_base, css="style.css", title="SEK - SOC Operations Room") as interface:
    
    with gr.Row():
        gr.Markdown("💻 **SEC Threat Intelligence System v3.0** | Console de Monitoramento Ativo")
    
    with gr.Row():
        # Lado Esquerdo - Painel de Controle Limpo
        with gr.Column(scale=1, elem_classes=["cyber-box"]):
            gr.Markdown("### 🎛️ PIPELINE CORPORATIVO")
            gr.Markdown("Execução integrada dos processadores técnicos de Threat Intelligence.")
            
            btn_disparar = gr.Button("Iniciar Pipeline", elem_classes=["neon-btn"])
            
            gr.Markdown("📊 **Engine Specs:**\n* ThreadPool: Active\n* API Status: Connected\n* Auto-Dedup: Enabled")
            
        # Lado Direito - O Monitor de Execução Real
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