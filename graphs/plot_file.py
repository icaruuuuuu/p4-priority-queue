import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configuração visual
sns.set_theme(style="whitegrid")

# 1. Carregar os datasets de transferência de arquivos
df_prio = pd.read_csv('ml/file-ml.csv')
df_noprio = pd.read_csv('non-ml/file-no-ml.csv')

# 2. Tratamento de dados nulos
df_prio = df_prio.dropna(subset=['timestamp', 'time_total'])
df_noprio = df_noprio.dropna(subset=['timestamp', 'time_total'])

# 3. Normalizar o tempo para iniciar em 0 segundos em ambos os testes
df_prio['tempo_decorrido'] = df_prio['timestamp'] - df_prio['timestamp'].min()
df_noprio['tempo_decorrido'] = df_noprio['timestamp'] - df_noprio['timestamp'].min()

# 4. Adicionar rótulos de identificação dos cenários
df_prio['Cenário'] = 'Com Fila de Prioridade (BMv2)'
df_noprio['Cenário'] = 'Sem Fila de Prioridade'

# 5. Unir os dados em uma única estrutura
df_combined = pd.concat([df_prio, df_noprio], ignore_index=True)

# 6. Plotar o gráfico de linha
plt.figure(figsize=(12, 6))

sns.lineplot(
    data=df_combined,
    x='tempo_decorrido',
    y='time_total',
    hue='Cenário',
    palette=['#1f77b4', '#ff7f0e'],
    linewidth=1.5,
    alpha=0.85
)

# 7. Ajustar títulos, rótulos e legendas
plt.title('Comparação de time_total (Download de Arquivo) ao Longo do Tempo', fontsize=14, fontweight='bold', pad=15)
plt.xlabel('Tempo Decorrido (segundos)', fontsize=12)
plt.ylabel('Time Total (segundos)', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)
plt.legend(title='Cenário', title_fontsize='11', fontsize='10')

# 8. Renderizar e salvar a imagem
plt.tight_layout()
plt.savefig('comparacao_file_time_total.png', dpi=300)
plt.show()
