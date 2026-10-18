import io
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def generate_status_card(cpu, ram, swap, disk, subtitle=None):
    fig, ax = plt.subplots(figsize=(7, 4.2), facecolor='#161922')
    ax.set_facecolor('#161922')

    labels = ['CPU', 'RAM', 'SWAP', 'DISK']
    values = [cpu, ram, swap, disk]
    colors = []
    
    for v in values:
        if v > 85:
            colors.append('#ff4d4f')  # Красный
        elif v > 65:
            colors.append('#faad14')  # Желтый
        else:
            colors.append('#00b96b')  # Зеленый

    y_pos = range(len(labels))
    bars = ax.barh(y_pos, values, color=colors, height=0.45, edgecolor='none')
    
    # Серые фоновые полосы (100%)
    ax.barh(y_pos, [100]*len(labels), color='#262a38', height=0.45, zorder=0)
    for bar in bars:
        bar.set_zorder(1)

    for threshold, tcolor in ((65, '#faad14'), (85, '#ff4d4f')):
        ax.axvline(threshold, color=tcolor, linewidth=0.8, linestyle='--', alpha=0.35, zorder=0)

    ax.set_xlim(0, 105)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, color='#ffffff', fontsize=12, fontweight='bold')
    ax.invert_yaxis()
    ax.tick_params(left=False, bottom=False, labelbottom=False)

    for i, v in enumerate(values):
        ax.text(v + 2, i, f"{v:.1f}%", va='center', color='#ffffff', fontsize=11, fontweight='bold')

    for spine in ax.spines.values():
        spine.set_visible(False)

    # Без эмодзи, чтобы не появлялись квадраты
    plt.title("СТАТУС РЕСУРСОВ VPS", color='#8b949e', fontsize=12, pad=18, fontweight='bold', loc='left')
    if subtitle:
        ax.text(0, 1.02, subtitle, transform=ax.transAxes, color='#6e7681', fontsize=9, va='bottom')
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=140, facecolor=fig.get_facecolor(), bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return buf


def generate_history_chart(rows, hours):
    """График CPU/RAM/Disk и сетевого трафика за период. rows: (ts, cpu, ram, swap, disk, rx, tx)."""
    import datetime
    msk = datetime.timezone(datetime.timedelta(hours=3))
    times = [datetime.datetime.fromtimestamp(r[0], msk) for r in rows]

    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(8, 5.6), facecolor='#161922',
        gridspec_kw={'height_ratios': [3, 2]}, sharex=True
    )
    for ax in (ax1, ax2):
        ax.set_facecolor('#161922')
        ax.grid(color='#262a38', linewidth=0.6)
        ax.tick_params(colors='#8b949e', labelsize=8)
        for spine in ax.spines.values():
            spine.set_color('#262a38')

    ax1.plot(times, [r[1] for r in rows], color='#00b96b', linewidth=1.4, label='CPU')
    ax1.plot(times, [r[2] for r in rows], color='#4096ff', linewidth=1.4, label='RAM')
    ax1.plot(times, [r[4] for r in rows], color='#faad14', linewidth=1.4, label='Disk')
    ax1.set_ylim(0, 100)
    ax1.set_ylabel('%', color='#8b949e')
    ax1.legend(loc='upper left', ncol=3, facecolor='#161922', edgecolor='#262a38', labelcolor='#ffffff', fontsize=8)

    ax2.fill_between(times, [r[5] for r in rows], color='#4096ff', alpha=0.35, label='Вх. КБ/с')
    ax2.fill_between(times, [r[6] for r in rows], color='#ff7a45', alpha=0.35, label='Исх. КБ/с')
    ax2.set_ylabel('КБ/с', color='#8b949e')
    ax2.legend(loc='upper left', ncol=2, facecolor='#161922', edgecolor='#262a38', labelcolor='#ffffff', fontsize=8)

    import matplotlib.dates as mdates
    fmt = '%H:%M' if hours <= 24 else '%d.%m %H:%M'
    ax2.xaxis.set_major_formatter(mdates.DateFormatter(fmt, tz=msk))
    fig.autofmt_xdate()

    label = f"{hours} ч." if hours < 48 else f"{hours // 24} дн."
    fig.suptitle(f"ИСТОРИЯ РЕСУРСОВ VPS ({label}, МСК)", color='#8b949e', fontsize=11, fontweight='bold', x=0.02, ha='left')
    fig.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=130, facecolor=fig.get_facecolor(), bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return buf
