import gradio as gr
import requests

def coletar_ips_maliciosos():
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        resposta = requests.get(url, headers=headers, timeout=10)
        
        if resposta.status_code == 200:
            linhas = resposta.text.split("\n")
            ips_filtrados = []
            
            # Garante que está usando 'linhas' (em português) sem o 's' no final
            for linha in linhas:
                linha = linha.strip()
                if linha and not linha.startswith("#"):
                    ips_filtrados.append(linha)
            
            total_ips = len(ips_filtrados)
            resultado_final = f"--- TOTAL DE IPs COMPROMETIDOS ATIVOS (Emerging Threats): {total_ips} ---\n\n"
            resultado_final += "\n".join(ips_filtrados)
            return resultado_final
        else:
            return f"Erro ao acessar o feed do Emerging Threats. Status Code: {resposta.status_code}"
            
    except Exception as e:
        return f"Falha na conexão com o feed de segurança: {str(e)}"

interface = gr.Interface(
    fn=coletar_ips_maliciosos,
    inputs=None,
    outputs=gr.Textbox(label="Lista de IPs para Blocklist (IoCs)", lines=25),
    title="🛡️ SOC Threat Intelligence - Coletor de IoCs",
    description="Clique no botão abaixo para buscar em tempo real a lista de IPs compromised e ativos do Emerging Threats (Proofpoint).",
    submit_btn="Buscar IPs Atualizados"
)

if __name__ == "__main__":
    interface.launch()