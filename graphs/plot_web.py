import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configuração visual do Seaborn
sns.set_theme(style="whitegrid")

# 1. Carregar os datasets
df_prio = pd.read_csv('ml/web-ml.csv')
df_noprio = pd.read_csv('non-ml/web-no-ml.csv')

# 2. Normalizar o tempo para iniciar em 0 segundos em ambos os testes
df_prio['tempo_decorrido'] = df_prio['timestamp'] - df_prio['timestamp'].min()
df_noprio['tempo_decorrido'] = df_noprio['timestamp'] - df_noprio['timestamp'].min()

# 3. Identificar os cenários para a legenda
df_prio['Cenário'] = 'Com Fila de Prioridade (BMv2)'
df_noprio['Cenário'] = 'Sem Fila de Prioridade'

# 4. Unir os DataFrames
df_combined = pd.concat([df_prio, df_noprio], ignore_index=True)

# 5. Criar a figura e plotar o gráfico de linha
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

# 6. Personalizar títulos e eixos
plt.title('Comparação de time_total (curl): Com vs Sem Fila de Prioridade', fontsize=14, fontweight='bold', pad=15)
plt.xlabel('Tempo Decorrido (segundos)', fontsize=12)
plt.ylabel('Time Total (segundos)', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)
plt.legend(title='Cenário', title_fontsize='11', fontsize='10')

# 7. Exibir/Salvar o gráfico
plt.tight_layout()
plt.savefig('comparacao_time_total.png', dpi=300)
plt.show()
