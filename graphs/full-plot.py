import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os

# ==========================================
# CONSTANTS & CONFIGURATIONS
# ==========================================

# Colors - Base
COLOR_ML = '#FF0072'      # Rosa forte e vibrante (DeepPink)
COLOR_NO_ML = '#00B9F6'   # Ciano dessaturado

# Colors - Combined Plot Variations
COLOR_ML_HTTP = COLOR_ML      # DeepPink
COLOR_ML_FTP = '#FF61A8'       # HotPink
COLOR_NO_ML_HTTP = COLOR_NO_ML   # Desaturated Cyan
COLOR_NO_ML_FTP = '#14E5FF'    # CadetBlue (Ciano mais fechado)

# File paths
FILE_HTTP_ML = 'ml/web-ml.csv'
FILE_HTTP_NO_ML = 'non-ml/web-no-ml.csv'
FILE_FTP_ML = 'ml/file-ml.csv'
FILE_FTP_NO_ML = 'non-ml/file-no-ml.csv'
FILE_VID_ML = 'ml/vid-ml.log'
FILE_VID_NO_ML = 'non-ml/vid-no-ml.log'

# Titles
TITLE_FPS = 'Time-Series: FPS (ML vs No-ML)'
TITLE_AREA = 'Cumulative Area: Frames (Total, Dup, Drop)'

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def parse_ffmpeg_log(filepath):
    if not os.path.exists(filepath):
        print(f"Warning: File {filepath} not found. Returning empty DataFrame.")
        return pd.DataFrame(columns=['timestamp', 'frame', 'fps', 'dup_frames', 'drop_frames'])
        
    data = []
    current_entry = {}
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            
            parts = line.split(', ')
            if len(parts) == 2:
                timestamp = int(parts[0])
                key_value = parts[1].split('=')
                
                if len(key_value) == 2:
                    key, value = key_value[0], key_value[1]
                    if key == 'frame' and current_entry:
                        data.append(current_entry)
                        current_entry = {}
                        
                    current_entry['timestamp'] = timestamp
                    try:
                        current_entry[key] = float(value) if '.' in value else int(value)
                    except ValueError:
                        current_entry[key] = value
                        
        if current_entry:
            data.append(current_entry)
            
    return pd.DataFrame(data)

def load_csv_data(filepath, label, protocol):
    if not os.path.exists(filepath):
        print(f"Warning: File {filepath} not found.")
        return pd.DataFrame()
    df = pd.read_csv(filepath)
    df['Label'] = label
    df['Protocol'] = protocol
    return df

def add_right_gradient(ax, x, y, color, x_max):
    """Cria um gradiente horizontal preenchendo o lado direito da linha (para CDF)."""
    n_steps = 40
    base_alpha = 0.25
    alpha_step = base_alpha / n_steps
    for i in range(n_steps):
        frac = i / (n_steps - 1)
        # O limite vai encolhendo de x_max até x, criando o "fade" até transparente
        x_bound = x_max - (x_max - x) * frac
        ax.fill_betweenx(y, x, x_bound, color=color, alpha=alpha_step, linewidth=0)

def add_bottom_gradient(ax, x, y, color, y_min=0):
    """Cria um gradiente vertical preenchendo a área abaixo da linha (para FPS)."""
    n_steps = 40
    base_alpha = 0.3
    alpha_step = base_alpha / n_steps
    for i in range(n_steps):
        frac = i / (n_steps - 1)
        # O limite cresce de y_min até y
        y_bound = y_min + (y - y_min) * frac
        ax.fill_between(x, y_bound, y, color=color, alpha=alpha_step, linewidth=0)

# ==========================================
# DATA LOADING
# ==========================================

df_http_ml = load_csv_data(FILE_HTTP_ML, 'ML', 'HTTP')
df_http_no_ml = load_csv_data(FILE_HTTP_NO_ML, 'No-ML', 'HTTP')
df_ftp_ml = load_csv_data(FILE_FTP_ML, 'ML', 'FTP')
df_ftp_no_ml = load_csv_data(FILE_FTP_NO_ML, 'No-ML', 'FTP')

df_network = pd.concat([df_http_ml, df_http_no_ml, df_ftp_ml, df_ftp_no_ml], ignore_index=True)

df_vid_ml = parse_ffmpeg_log(FILE_VID_ML)
df_vid_no_ml = parse_ffmpeg_log(FILE_VID_NO_ML)

# ==========================================
# PLOTTING: SEPARATED BY PROTOCOL
# ==========================================
sns.set_theme(style="whitegrid")
palette = {'ML': COLOR_ML, 'No-ML': COLOR_NO_ML}

if not df_network.empty and 'time_total' in df_network.columns:
    # 1. Box Plots Separados
    for protocol in ['HTTP', 'FTP']:
        plt.figure(figsize=(8, 6))
        subset = df_network[df_network['Protocol'] == protocol]
        sns.boxplot(data=subset, x='Label', y='time_total', palette=palette)
        plt.title(f'Box Plot: Total Time ({protocol})')
        plt.ylabel('Total Time (s)')
        plt.xlabel('Condition')
        plt.tight_layout()
        plt.savefig(f'box_plot_time_total_{protocol.lower()}', dpi=300)
        plt.close()

    # 2. CDFs Separados (com Gradiente)
    for protocol in ['HTTP', 'FTP']:
        fig, ax = plt.subplots(figsize=(8, 6))
        subset_prot = df_network[df_network['Protocol'] == protocol]
        max_x = subset_prot['time_total'].max() * 1.05 if not subset_prot.empty else 1
        
        for label, color in zip(['ML', 'No-ML'], [COLOR_ML, COLOR_NO_ML]):
            subset = subset_prot[subset_prot['Label'] == label]
            if not subset.empty:
                x = np.sort(subset['time_total'])
                y = np.arange(1, len(x) + 1) / len(x)
                ax.plot(x, y, linestyle='-', color=color, label=f'{label}')
                add_right_gradient(ax, x, y, color, max_x)
                
        ax.set_title(f'CDF: Total Time ({protocol})')
        ax.set_xlabel('Total Time (s)')
        ax.set_ylabel('CDF')
        ax.set_xlim(right=max_x)
        ax.legend()
        plt.tight_layout()
        plt.savefig(f'cdf_time_total_{protocol.lower()}', dpi=300)
        plt.show()

    # 3. Error Bars Separados
    stats = df_network.groupby(['Protocol', 'Label'])['time_total'].agg(['mean', 'std']).reset_index()
    for protocol in ['HTTP', 'FTP']:
        plt.figure(figsize=(8, 6))
        prot_stats = stats[stats['Protocol'] == protocol]
        for label, color in zip(['ML', 'No-ML'], [COLOR_ML, COLOR_NO_ML]):
            subset = prot_stats[prot_stats['Label'] == label]
            if not subset.empty:
                mean_val = subset['mean'].values[0]
                std_val = subset['std'].values[0]
                lower_error = max(min(mean_val, std_val), 0.1)
                upper_error = std_val
                plt.bar(subset['Label'], mean_val, yerr=[[lower_error], [upper_error]], 
                        color=color, label=label, capsize=8,
                        error_kw={'ecolor': 'black', 'elinewidth': 2, 'capthick': 2})
        plt.title(f'Mean Total Time with Error Bars ({protocol})')
        plt.ylabel('Mean Total Time (s)')
        plt.xlabel('Condition')
        plt.ylim(bottom=0) 
        plt.tight_layout()
        plt.savefig(f'error_bar_time_total_{protocol.lower()}', dpi=300)
        plt.close()

# ==========================================
# PLOTTING: COMBINED DATA (ALL IN ONE)
# ==========================================
if not df_network.empty and 'time_total' in df_network.columns:
    
    # 4. Combined Box Plot
    plt.figure(figsize=(8, 6))
    sns.boxplot(data=df_network, x='Protocol', y='time_total', hue='Label', palette=palette)
    plt.title('Box Plot: Total Time (HTTP & FTP)')
    plt.ylabel('Total Time (s)')
    plt.tight_layout()
    plt.savefig('box_plot_time_total_combined', dpi=300)
    plt.close()

    # 5. Combined Violin Plot
    plt.figure(figsize=(8, 6))
    sns.violinplot(data=df_network, x='Protocol', y='time_total', hue='Label', palette=palette, split=True, inner="quart")
    plt.title('Violin Plot: Total Time (HTTP & FTP)')
    plt.ylabel('Total Time (s)')
    plt.tight_layout()
    plt.savefig('violin_plot_time_total_combined', dpi=300)
    plt.close()

    # 6. Combined CDF (Linhas contínuas, 4 cores e Gradiente)
    fig, ax = plt.subplots(figsize=(8, 6))
    max_x = df_network['time_total'].max() * 1.05
    
    color_map = {
        ('HTTP', 'ML'): COLOR_ML_HTTP,
        ('FTP', 'ML'): COLOR_ML_FTP,
        ('HTTP', 'No-ML'): COLOR_NO_ML_HTTP,
        ('FTP', 'No-ML'): COLOR_NO_ML_FTP
    }
    
    for protocol in ['HTTP', 'FTP']:
        for label in ['ML', 'No-ML']:
            subset = df_network[(df_network['Protocol'] == protocol) & (df_network['Label'] == label)]
            if not subset.empty:
                x = np.sort(subset['time_total'])
                y = np.arange(1, len(x) + 1) / len(x)
                c = color_map[(protocol, label)]
                # Mantendo linha contínua ('-') para todos, diferenciados pelas 4 cores
                ax.plot(x, y, linestyle='-', color=c, label=f'{protocol} {label}')
                add_right_gradient(ax, x, y, c, max_x)
                
    ax.set_title('CDF: Total Time (HTTP & FTP)')
    ax.set_xlabel('Total Time (s)')
    ax.set_ylabel('CDF')
    ax.set_xlim(right=max_x)
    ax.legend()
    plt.tight_layout()
    plt.savefig('cdf_time_total_combined', dpi=300)
    plt.show()

    # 7. Combined Error Bars (Grouped Bar Chart)
    plt.figure(figsize=(8, 6))
    protocols = ['HTTP', 'FTP']
    x_indices = np.arange(len(protocols))
    width = 0.35 
    
    for i, (label, color) in enumerate(zip(['ML', 'No-ML'], [COLOR_ML, COLOR_NO_ML])):
        means = []
        lower_errors = []
        upper_errors = []
        
        for protocol in protocols:
            subset = stats[(stats['Protocol'] == protocol) & (stats['Label'] == label)]
            if not subset.empty:
                mean_val = subset['mean'].values[0]
                std_val = subset['std'].values[0]
                means.append(mean_val)
                lower_errors.append(max(min(mean_val, std_val), 0.1))
                upper_errors.append(std_val)
            else:
                means.append(0); lower_errors.append(0); upper_errors.append(0)
                
        offset = -width/2 if i == 0 else width/2
        plt.bar(x_indices + offset, means, width, yerr=[lower_errors, upper_errors], 
                color=color, label=label, capsize=8,
                error_kw={'ecolor': 'black', 'elinewidth': 2, 'capthick': 2})

    plt.title('Mean Total Time with Error Bars (HTTP & FTP)')
    plt.ylabel('Mean Total Time (s)')
    plt.xlabel('Protocol')
    plt.xticks(x_indices, protocols)
    plt.legend()
    plt.ylim(bottom=0)
    plt.tight_layout()
    plt.savefig('error_bar_time_total_combined', dpi=300)
    plt.close()

# ==========================================
# PLOTTING: VIDEO LOGS
# ==========================================

# 8. Time-Series for FPS (com Gradiente Inferior)
fig, ax = plt.subplots(figsize=(10, 5))

if not df_vid_ml.empty and 'fps' in df_vid_ml.columns:
    # Assegurando que os dados sejam float para preenchimento consistente
    x_ml = (df_vid_ml['timestamp'] - df_vid_ml['timestamp'].min()).astype(float).values
    y_ml = df_vid_ml['fps'].astype(float).values
    ax.plot(x_ml, y_ml, color=COLOR_ML, label='ML')
    add_bottom_gradient(ax, x_ml, y_ml, COLOR_ML)
    
if not df_vid_no_ml.empty and 'fps' in df_vid_no_ml.columns:
    x_noml = (df_vid_no_ml['timestamp'] - df_vid_no_ml['timestamp'].min()).astype(float).values
    y_noml = df_vid_no_ml['fps'].astype(float).values
    ax.plot(x_noml, y_noml, color=COLOR_NO_ML, label='No-ML')
    add_bottom_gradient(ax, x_noml, y_noml, COLOR_NO_ML)

ax.set_title(TITLE_FPS)
ax.set_xlabel('Time (s)')
ax.set_ylabel('FPS')
ax.legend()
plt.tight_layout()
plt.savefig('time_series_fps', dpi=300)
plt.show()

# 9. Cumulative Area for frames
if not df_vid_ml.empty and all(c in df_vid_ml.columns for c in ['frame', 'dup_frames', 'drop_frames']):
    plt.figure(figsize=(10, 5))
    x = df_vid_ml['timestamp'] - df_vid_ml['timestamp'].min()
    y_frame = df_vid_ml['frame']
    y_dup = df_vid_ml['dup_frames']
    y_drop = df_vid_ml['drop_frames']
    
    plt.stackplot(x, y_frame, y_dup, y_drop, 
                  labels=['Total Frames', 'Duplicated', 'Dropped'],
                  colors=[COLOR_ML, '#ff6666', '#cc0000'], alpha=0.7)
    
    plt.title(f"{TITLE_AREA} (ML)")
    plt.xlabel('Time (s)')
    plt.ylabel('Cumulative Frame Count')
    plt.legend(loc='upper left')
    plt.tight_layout()
    plt.savefig('frame_cumulative_area', dpi=300)
    plt.show()
