
import datetime
from typing import Counter, Optional

from matplotlib import pyplot as plt
import numpy as np
from pydantic import BaseModel, RootModel
from sklearn.metrics import ConfusionMatrixDisplay, confusion_matrix, f1_score, precision_recall_fscore_support

class ServerIdentity(BaseModel):
    id: int
    country: str
    origin: str
    ip_v4: Optional[str] = None
    ip_v6: Optional[str] = None

    def __eq__(self, other):
        return other and self.id == other.id and self.origin == other.origin

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
      return hash((self.id, self.origin))
    
class Servers(RootModel):
    root: list[ServerIdentity] = []

    def add(self, object): self.root.append(object)
    def __len__(self): return len(self.root)

class Measure(BaseModel):
    id: int
    origin: str
    ground_truth: str 
    guess: Optional[str] = None
    ip_v4: Optional[str] = None
    ip_v6: Optional[str] = None
    latency: float
    hops: float
    count: int
    date_time: datetime.datetime = datetime.datetime.now()

def create_bar_chart_multi_models(data, predictions, least_common=False):
    counter = Counter(data)
    total = len(data)

    top5 = counter.most_common()[-5:]
    if not least_common:
        top5 = counter.most_common(5)
    
    top5_classes = [cls for cls, _ in top5]
    top5_percent = [cnt / total * 100 for _, cnt in top5]

    x_labels = [f"{cls}\n({pct:.1f}%)" for cls, pct in zip(top5_classes, top5_percent)]

    model_names = []
    f1_scores = []  # list of lists, each inner list corresponds to one model

    for name, y_true, y_pred in predictions:
        _, _, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=top5_classes, zero_division=0
    )
        model_names.append(name)
        f1_scores.append(f1)

    # 3. Grouped bar chart
    x = np.arange(len(top5_classes))
    width = 0.8 / len(model_names)
    multiplier = 0

    fig, ax = plt.subplots(figsize=(10, 6))
    for i, (model, scores) in enumerate(zip(model_names, f1_scores)):
        offset = width * multiplier
        rects = ax.bar(x + offset, scores, width, label=model)
        ax.bar_label(rects, fmt='%.2f', padding=2, fontsize=8)
        multiplier += 1

    ax.set_ylabel('F1 Score')
    if not least_common:
        ax.set_title('F1 Score per Model for the 5 Most Frequent Countries')
    else:
        ax.set_title('F1 Score per Model for the 5 Least Frequent Countries')
    ax.set_xticks(x + width * (len(model_names) - 1) / 2, x_labels)
    ax.legend(loc='lower right')
    ax.set_ylim(0, 1.0)
    plt.tight_layout()
    plt.show()

import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
from sklearn.metrics import f1_score

def create_frequency_bar_chart(data, predictions, n=20):
    counter = Counter(data["ground_truth"])
    total = len(data)

    top_classes = [cls for cls, _ in counter.most_common(n)]

    class_counts = [counter[cls] for cls in top_classes]
    class_percent = [cnt / total * 100 for cnt in class_counts]
    labels = [f"{cls}\n({pct:.1f}%)" for cls, pct in zip(top_classes, class_percent)]

    f1_scores = []
    for cls in top_classes:
        y_true_bin = (data["ground_truth"] == cls).astype(int)
        y_pred_bin = (predictions == cls).astype(int)
        f1 = f1_score(y_true_bin, y_pred_bin, zero_division=0)
        f1_scores.append(f1)

    fig, ax = plt.subplots(figsize=(12, 6))
    x_pos = np.arange(len(top_classes))
    bars = ax.bar(x_pos, f1_scores, color='steelblue')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.set_ylabel('F1 Score')
    ax.set_title(f'F1 Score for {n} Most Frequent Countries')
    ax.set_ylim(0, 1.0)

    for bar, score in zip(bars, f1_scores):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{score:.2f}', ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.show()

def create_best_performing_bar_chart(data, predictions, n=20):
    classes = data["ground_truth"].unique()
    total = len(data)
    class_counts = data["ground_truth"].value_counts()

    f1_scores = {}
    for cls in classes:
        y_true_bin = (data["ground_truth"] == cls).astype(int)
        y_pred_bin = (predictions == cls).astype(int)
        f1 = f1_score(y_true_bin, y_pred_bin, zero_division=0)
        f1_scores[cls] = f1

    sorted_items = sorted(f1_scores.items(), key=lambda x: x[1], reverse=True)[:n]
    top_classes = [cls for cls, _ in sorted_items]
    top_f1 = [score for _, score in sorted_items]
    percentages = [class_counts[cls] / total * 100 for cls in top_classes]

    labels = [f"{cls}\n({pct:.1f}%)" for cls, pct in zip(top_classes, percentages)]

    fig, ax = plt.subplots(figsize=(12, 6))
    x_pos = np.arange(len(top_classes))
    bars = ax.bar(x_pos, top_f1, color='forestgreen')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.set_ylabel('F1 Score')
    ax.set_title(f'Top {n} Best Performing Countries (by F1 Score)')
    ax.set_ylim(0, 1.0)

    for bar, score in zip(bars, top_f1):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{score:.2f}', ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.show()