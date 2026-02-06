"""
Report Generator for Detection Comparison
==========================================
Produces terminal tables, JSON, Discord digest, and HTML report
with interactive Plotly charts and SHAP beeswarm plots.

Author: Brian Chaplow
"""

import json
import logging
from typing import Dict, Optional, List
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


# =============================================================================
# TERMINAL REPORT
# =============================================================================

def generate_terminal_report(results: Dict):
    """Print formatted multi-model comparison to terminal."""
    from tabulate import tabulate

    print("\n" + "=" * 75)
    print("  MULTI-MODEL DETECTION COMPARISON REPORT")
    print("=" * 75)

    meta = results['metadata']
    print(f"\n  Records: {meta['total_records']:,}  |  "
          f"Attacks: {meta['attack_records']:,}  |  "
          f"Models: {len(meta['models_compared'])}  |  "
          f"Threshold: {meta['threshold']}")

    # Rankings table
    rankings = results.get('cross_model', {}).get('rankings', {}).get('by_pr_auc', [])
    if rankings:
        print("\n### Model Rankings (by PR-AUC) ###\n")
        table_data = []
        for i, r in enumerate(rankings, 1):
            table_data.append([
                i, r['model'],
                f"{r['pr_auc']:.4f}",
                f"{r['recall']:.4f}",
                f"{r['precision']:.4f}",
                f"{r['f1']:.4f}",
            ])

        # Add Suricata row
        sur = results.get('suricata', {}).get('detection_rates', {})
        table_data.append([
            '*', 'Suricata (rules)',
            '--',
            f"{sur.get('recall', 0):.4f}",
            f"{sur.get('precision', 0):.4f}",
            f"{sur.get('f1_score', 0):.4f}",
        ])

        print(tabulate(
            table_data,
            headers=['#', 'Model', 'PR-AUC', 'Recall', 'Precision', 'F1'],
            tablefmt='simple',
        ))

    # Category x Model matrix
    cat_matrix = results.get('cross_model', {}).get('category_model_matrix', {})
    if cat_matrix:
        print("\n### Detection Rate by Category (%) ###\n")
        model_names = results['metadata']['models_compared']
        headers = ['Category', 'N', 'Suricata'] + model_names

        table_data = []
        for cat, stats in sorted(cat_matrix.items(), key=lambda x: x[1].get('total_attacks', 0), reverse=True):
            row = [
                cat[:20],
                stats.get('total_attacks', 0),
                f"{stats.get('suricata', 0):.1f}",
            ]
            for m in model_names:
                row.append(f"{stats.get(m, 0):.1f}")
            table_data.append(row)

        print(tabulate(table_data, headers=headers, tablefmt='simple'))

    # Consensus
    consensus = results.get('cross_model', {}).get('consensus_matrix', {})
    if consensus:
        print("\n### Consensus Analysis ###\n")
        print(f"  Detected by all:      {consensus.get('detected_by_all', 0):>6}")
        print(f"  Detected by majority: {consensus.get('detected_by_majority', 0):>6}")
        print(f"  Detected by minority: {consensus.get('detected_by_minority', 0):>6}")
        print(f"  Blind spots (none):   {consensus.get('detected_by_none', 0):>6}")

    # Recommendations
    recs = results.get('recommendations', [])
    if recs:
        print("\n### Recommendations ###\n")
        for i, rec in enumerate(recs, 1):
            print(f"  {i}. {rec}\n")

    print("=" * 75)


# =============================================================================
# JSON REPORT
# =============================================================================

def save_json_report(results: Dict, output_path: str):
    """Save results as formatted JSON."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"JSON report saved to {output_path}")


# =============================================================================
# DISCORD DIGEST
# =============================================================================

def format_discord_digest(results: Dict) -> Dict:
    """Format results as a Discord webhook embed payload."""
    meta = results['metadata']
    rankings = results.get('cross_model', {}).get('rankings', {}).get('by_pr_auc', [])
    consensus = results.get('cross_model', {}).get('consensus_matrix', {})
    blind_spots = results.get('cross_model', {}).get('blind_spots', {}).get('total', 0)

    # Build description
    lines = [f"**Records:** {meta['total_records']:,} ({meta['attack_records']:,} attacks)"]
    lines.append(f"**Models Compared:** {len(meta['models_compared'])}")
    lines.append("")

    if rankings:
        lines.append("**Model Rankings (PR-AUC):**")
        for i, r in enumerate(rankings[:5], 1):
            medal = ['\U0001f947', '\U0001f948', '\U0001f949'][i - 1] if i <= 3 else f"{i}."
            lines.append(f"{medal} {r['model']}: {r['pr_auc']:.4f} PR-AUC | {r['recall']:.1%} recall")

    sur = results.get('suricata', {}).get('detection_rates', {})
    lines.append(f"\nSuricata (rules): {sur.get('recall', 0):.1%} recall | {sur.get('precision', 0):.1%} precision")

    if consensus:
        lines.append(f"\n**Consensus:** {consensus.get('detected_by_all', 0)} by all, "
                     f"{consensus.get('detected_by_none', 0)} blind spots")

    if blind_spots > 0:
        lines.append(f"\n**ALERT:** {blind_spots} attacks evade ALL detection systems")

    description = "\n".join(lines)

    # Color: green if no blind spots, yellow if some, red if many
    if blind_spots == 0:
        color = 3066993  # green
    elif blind_spots < 10:
        color = 16776960  # yellow
    else:
        color = 15158332  # red

    return {
        'embeds': [{
            'title': 'Detection Comparison Complete',
            'description': description,
            'color': color,
            'footer': {'text': f"Threshold: {meta['threshold']} | {meta.get('timestamp', '')}"},
        }]
    }


def send_discord_digest(results: Dict, webhook_url: str):
    """Send digest to Discord webhook."""
    import subprocess

    payload = format_discord_digest(results)
    payload_json = json.dumps(payload)

    subprocess.run([
        'curl', '-s',
        '-H', 'Content-Type: application/json',
        '-X', 'POST', webhook_url,
        '-d', payload_json,
    ], capture_output=True)

    logger.info("Discord digest sent")


# =============================================================================
# HTML REPORT
# =============================================================================

def generate_html_report(
    results: Dict,
    output_path: str,
    shap_data: Optional[Dict] = None,
):
    """
    Generate self-contained HTML report with Plotly charts.

    Args:
        results: Full comparison results dict
        output_path: Path to write HTML file
        shap_data: Optional dict of {model_name: {'shap_values': array, 'feature_names': list, 'X_sample': array}}
    """
    charts_html = []

    # --- Chart 1: Model Radar ---
    charts_html.append(_chart_radar(results))

    # --- Chart 2: Category x Model Heatmap ---
    charts_html.append(_chart_category_heatmap(results))

    # --- Chart 3: Agreement Heatmap ---
    charts_html.append(_chart_agreement_heatmap(results))

    # --- Chart 4: Consensus Bars ---
    charts_html.append(_chart_consensus_bars(results))

    # --- Chart 5: PR Curves (if threshold analysis available) ---
    charts_html.append(_chart_threshold_analysis(results))

    # --- Chart 6: Confusion Matrices ---
    charts_html.append(_chart_confusion_matrices(results))

    # --- Chart 7: SHAP Beeswarm (if data provided) ---
    if shap_data:
        charts_html.append(_chart_shap_beeswarm(shap_data))

    # Assemble HTML
    html = _assemble_html(results, charts_html)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(html)

    logger.info(f"HTML report saved to {output_path}")


def _chart_radar(results: Dict) -> str:
    """Radar chart comparing all models + Suricata."""
    import plotly.graph_objects as go

    rankings = results.get('cross_model', {}).get('rankings', {}).get('by_pr_auc', [])
    sur = results.get('suricata', {}).get('detection_rates', {})

    categories = ['Recall', 'Precision', 'F1', 'Detection Rate']

    fig = go.Figure()

    for r in rankings:
        fig.add_trace(go.Scatterpolar(
            r=[r['recall'], r['precision'], r['f1'], r['recall']],
            theta=categories,
            fill='toself',
            name=r['model'],
            opacity=0.6,
        ))

    # Suricata
    fig.add_trace(go.Scatterpolar(
        r=[sur.get('recall', 0), sur.get('precision', 0), sur.get('f1_score', 0), sur.get('recall', 0)],
        theta=categories,
        fill='toself',
        name='Suricata',
        opacity=0.6,
        line=dict(dash='dash'),
    ))

    fig.update_layout(
        polar=dict(bgcolor='rgba(0,0,0,0)', radialaxis=dict(visible=True, range=[0, 1])),
        title='Model Performance Radar',
        template='plotly_dark',
        height=500,
    )

    return f'<div class="chart-section" id="radar"><h2>Model Performance Radar</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_category_heatmap(results: Dict) -> str:
    """Category x Model detection rate heatmap."""
    import plotly.graph_objects as go

    cat_matrix = results.get('cross_model', {}).get('category_model_matrix', {})
    if not cat_matrix:
        return '<div class="chart-section" id="categories"><h2>Category Detection Heatmap</h2><p>No category data available.</p></div>'

    model_names = ['suricata'] + results['metadata']['models_compared']
    categories = sorted(cat_matrix.keys())

    z = []
    for cat in categories:
        row = [cat_matrix[cat].get(m, 0) for m in model_names]
        z.append(row)

    fig = go.Figure(data=go.Heatmap(
        z=z, x=model_names, y=categories,
        colorscale='RdYlGn', zmin=0, zmax=100,
        text=[[f'{v:.1f}%' for v in row] for row in z],
        texttemplate='%{text}',
        hovertemplate='%{y} / %{x}: %{z:.1f}%<extra></extra>',
    ))

    fig.update_layout(
        title='Detection Rate by Category (%)',
        template='plotly_dark',
        height=max(400, len(categories) * 40),
    )

    return f'<div class="chart-section" id="categories"><h2>Detection Rate by Category</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_agreement_heatmap(results: Dict) -> str:
    """Pairwise model agreement heatmap."""
    import plotly.graph_objects as go

    heatmap_data = results.get('cross_model', {}).get('agreement_heatmap', {})
    if not heatmap_data:
        return '<div class="chart-section" id="agreement"><h2>Model Agreement Heatmap</h2><p>No agreement data.</p></div>'

    model_names = list(heatmap_data.keys())
    z = [[heatmap_data[a].get(b, 0) for b in model_names] for a in model_names]

    fig = go.Figure(data=go.Heatmap(
        z=z, x=model_names, y=model_names,
        colorscale='Blues', zmin=0.5, zmax=1.0,
        text=[[f'{v:.2f}' for v in row] for row in z],
        texttemplate='%{text}',
    ))

    fig.update_layout(
        title='Pairwise Model Agreement',
        template='plotly_dark',
        height=400,
    )

    return f'<div class="chart-section" id="agreement"><h2>Model Agreement Heatmap</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_consensus_bars(results: Dict) -> str:
    """Consensus distribution bar chart."""
    import plotly.graph_objects as go

    consensus = results.get('cross_model', {}).get('consensus_matrix', {})
    dist = consensus.get('distribution', {})

    if not dist:
        return '<div class="chart-section" id="consensus"><h2>Detection Consensus</h2><p>No consensus data.</p></div>'

    x_labels = [f'{k} detectors' for k in sorted(dist.keys(), key=int)]
    values = [dist[k] for k in sorted(dist.keys(), key=int)]

    colors = ['#ff4444'] + ['#ff8800'] * 2 + ['#ffcc00'] * 2 + ['#44bb44'] * (len(values) - 4) if len(values) > 4 else ['#44bb44'] * len(values)
    colors[0] = '#ff4444'  # None = red

    fig = go.Figure(data=go.Bar(
        x=x_labels, y=values,
        marker_color=colors[:len(values)],
        text=values, textposition='auto',
    ))

    fig.update_layout(
        title='Attack Detection Consensus',
        xaxis_title='Number of Detectors',
        yaxis_title='Number of Attacks',
        template='plotly_dark',
        height=400,
    )

    return f'<div class="chart-section" id="consensus"><h2>Detection Consensus</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_threshold_analysis(results: Dict) -> str:
    """Threshold sweep curves for each model."""
    import plotly.graph_objects as go

    fig = go.Figure()
    has_data = False

    for model_name, model_data in results.get('models', {}).items():
        thresh_analysis = model_data.get('threshold_analysis', [])
        if not thresh_analysis:
            continue

        has_data = True
        thresholds = [t['threshold'] for t in thresh_analysis]
        recalls = [t['recall'] for t in thresh_analysis]
        precisions = [t['precision'] for t in thresh_analysis]

        fig.add_trace(go.Scatter(
            x=recalls, y=precisions,
            mode='lines+markers',
            name=model_name,
            text=[f'thresh={t:.2f}' for t in thresholds],
            hovertemplate='%{text}<br>Recall: %{x:.3f}<br>Precision: %{y:.3f}<extra>%{fullData.name}</extra>',
        ))

    if not has_data:
        return '<div class="chart-section" id="pr-curves"><h2>Precision-Recall Curves</h2><p>No threshold data available.</p></div>'

    fig.update_layout(
        title='Precision-Recall Tradeoff by Threshold',
        xaxis_title='Recall',
        yaxis_title='Precision',
        template='plotly_dark',
        height=500,
    )

    return f'<div class="chart-section" id="pr-curves"><h2>Precision-Recall Curves</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_confusion_matrices(results: Dict) -> str:
    """Small multiple confusion matrices."""
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    models = results.get('models', {})
    n_models = len(models)
    if n_models == 0:
        return '<div class="chart-section" id="confusion"><h2>Confusion Matrices</h2><p>No model data.</p></div>'

    cols = min(n_models, 4)
    rows = (n_models + cols - 1) // cols

    fig = make_subplots(rows=rows, cols=cols, subplot_titles=list(models.keys()))

    for idx, (model_name, model_data) in enumerate(models.items()):
        dr = model_data.get('detection_rates', {})
        tp = dr.get('true_positives', 0)
        fp = dr.get('false_positives', 0)
        fn = dr.get('false_negatives', 0)
        tn = dr.get('true_negatives', 0)

        row = idx // cols + 1
        col = idx % cols + 1

        fig.add_trace(go.Heatmap(
            z=[[tn, fp], [fn, tp]],
            x=['Predicted Benign', 'Predicted Attack'],
            y=['Actual Benign', 'Actual Attack'],
            colorscale='Blues',
            showscale=False,
            text=[[str(tn), str(fp)], [str(fn), str(tp)]],
            texttemplate='%{text}',
        ), row=row, col=col)

    fig.update_layout(
        title='Confusion Matrices',
        template='plotly_dark',
        height=300 * rows,
    )

    return f'<div class="chart-section" id="confusion"><h2>Confusion Matrices</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_shap_beeswarm(shap_data: Dict) -> str:
    """SHAP beeswarm plots embedded as base64 images."""
    import shap
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import base64
    from io import BytesIO

    html_parts = ['<div class="chart-section" id="shap"><h2>SHAP Feature Impact (Beeswarm)</h2>']

    for model_name, data in shap_data.items():
        shap_values = data['shap_values']
        feature_names = data['feature_names']
        X_sample = data['X_sample']

        plt.figure(figsize=(10, 8))
        shap.summary_plot(
            shap_values, X_sample,
            feature_names=feature_names,
            show=False,
            max_display=20,
            plot_type='dot',
        )
        plt.title(f'{model_name} — SHAP Feature Impact')
        plt.tight_layout()

        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                    facecolor='#1a1a2e', edgecolor='none')
        plt.close()
        buf.seek(0)

        img_b64 = base64.b64encode(buf.read()).decode('utf-8')
        html_parts.append(
            f'<div class="shap-plot"><h3>{model_name}</h3>'
            f'<img src="data:image/png;base64,{img_b64}" alt="SHAP beeswarm for {model_name}" '
            f'style="max-width:100%;border-radius:8px;"/></div>'
        )

    html_parts.append('</div>')
    return '\n'.join(html_parts)


def _assemble_html(results: Dict, charts: List[str]) -> str:
    """Assemble final HTML document with dark theme."""
    meta = results['metadata']
    recs = results.get('recommendations', [])

    recs_html = ''.join(f'<li>{r}</li>' for r in recs)

    charts_html = '\n'.join(charts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Detection Comparison Report — {meta.get('timestamp', '')[:10]}</title>
    <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid #30363d;
            margin-bottom: 2rem;
        }}
        header h1 {{
            color: #58a6ff;
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        header .meta {{
            color: #8b949e;
            font-size: 0.9rem;
        }}
        nav {{
            position: fixed;
            left: 0;
            top: 0;
            width: 220px;
            height: 100vh;
            background: #161b22;
            border-right: 1px solid #30363d;
            padding: 1rem;
            overflow-y: auto;
            z-index: 100;
        }}
        nav a {{
            display: block;
            color: #8b949e;
            text-decoration: none;
            padding: 0.4rem 0.8rem;
            border-radius: 4px;
            margin-bottom: 0.2rem;
            font-size: 0.85rem;
        }}
        nav a:hover {{ background: #30363d; color: #c9d1d9; }}
        .main {{ margin-left: 240px; }}
        .chart-section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .chart-section h2 {{
            color: #58a6ff;
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }}
        .recommendations {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
        }}
        .recommendations h2 {{ color: #58a6ff; margin-bottom: 1rem; }}
        .recommendations li {{
            margin-bottom: 0.8rem;
            padding-left: 0.5rem;
        }}
        .shap-plot {{ margin: 1rem 0; }}
        .shap-plot h3 {{ color: #c9d1d9; margin-bottom: 0.5rem; }}
        @media (max-width: 768px) {{
            nav {{ display: none; }}
            .main {{ margin-left: 0; }}
        }}
    </style>
</head>
<body>
    <nav>
        <h3 style="color:#58a6ff;margin-bottom:1rem;">Sections</h3>
        <a href="#top">Overview</a>
        <a href="#radar">Performance Radar</a>
        <a href="#categories">Category Heatmap</a>
        <a href="#agreement">Agreement</a>
        <a href="#consensus">Consensus</a>
        <a href="#pr-curves">PR Curves</a>
        <a href="#confusion">Confusion Matrices</a>
        <a href="#shap">SHAP Analysis</a>
        <a href="#recommendations">Recommendations</a>
    </nav>
    <div class="main">
        <div class="container">
            <header id="top">
                <h1>Detection Comparison Report</h1>
                <div class="meta">
                    {meta['total_records']:,} records | {meta['attack_records']:,} attacks |
                    {len(meta['models_compared'])} models | threshold {meta['threshold']} |
                    {meta.get('timestamp', '')[:19]}
                </div>
            </header>

            {charts_html}

            <div class="recommendations" id="recommendations">
                <h2>Recommendations</h2>
                <ol>{recs_html}</ol>
            </div>
        </div>
    </div>
</body>
</html>"""
