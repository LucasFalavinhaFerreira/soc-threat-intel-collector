import gradio as gr
import requests
from concurrent.futures import ThreadPoolExecutor

# Dicionário mapeando o nome do Feed para a sua respectiva URL de texto puro
FEEDS_CTI = {
    "Proofpoint (Emerging Threats)": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" ,
    "Blocklist.de (Ataques Recentes)": "https://lists.blocklist.de/lists/all.txt",
    "Tor Exit Nodes (Nós de Saída)": "https://check.torproject.org/exit-addresses"
}

def requisitar_feed(nome_feed, url):
    """Função isolada para buscar dados de um feed específico."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        resposta = requests.get(url, headers=headers, timeout=8)
        if resposta.status_code == 200:
            return nome_feed, resposta.text.split("\n")
    except Exception:
        pass
    return nome_feed, []

def agregar_threat_intelligence():
    ips_totais = set() # Usamos um SET para garantir que IPs duplicados sejam eliminados automaticamente
    logs_consolidacao = []
    
    # Dispara as requisições em paralelo usando Threads
    with ThreadPoolExecutor(max_workers=3) as executor:
        futuros = [executor.submit(requisitar_feed, nome, url) for nome, url in FEEDS_CTI.items()]
        
        for futuro in futuros:
            nome_feed, linhas = futuro.result()
            ips_do_feed = 0
            
            for linha in linhas:
                linha = linha.strip()
                if not linha or linha.startswith("#"):
                    continue
                
                # Tratamento específico para o formato da lista do Tor
                if nome_feed == "Tor Exit Nodes (Nós de Saída)":
                    if linha.startswith("ExitAddress"):
                        ip = linha.split()[1]
                        ips_totais.add(ip)
                        ips_do_feed += 1
                else:
                    # Formato padrão (um IP por linha)
                    if not linha.isalpha() and "." in linha: # Filtro básico para validar se parece um IP
                        ips_totais.add(linha)
                        ips_do_feed += 1
                        
            logs_consolidacao.append(f"✔️ {nome_feed}: {ips_do_feed} IPs processados.")

    # Converte de volta para lista ordenada
    lista_final = sorted(list(ips_totais))
    
    # Monta o relatório final na tela
    resultado = "--- status da consolidação multilista ---\n"
    resultado += "\n".join(logs_consolidacao) + "\n"
    resultado += f"\n🔥 Total de IPs Únicos e Consolidados (Sem Duplicadas): {len(lista_final)}\n"
    resultado += "-----------------------------------------\n\n"
    resultado += "\n".join(lista_final)
    
    return resultado

# Interface Gráfica do Gradio
interface = gr.Interface(
    fn=agregar_threat_intelligence,
    inputs=None,
    outputs=gr.Textbox(label="Painel de IoCs Consolidados (Blocklist Global)", lines=25),
    title="🛡️ SOC Threat Intelligence - Agregador Multifeed v2.0",
    description="Engine paralela (Multithreading) que coleta, limpa, remove duplicatas e consolida listas de IPs maliciosos de múltiplos vendors globais em tempo real.",
    submit_btn="Disparar Varredura Global"
)

if __name__ == "__main__":
    interface.launch()