"""Alarm-group classifier sub-package.

Provides a Random-Forest classifier that operates on **whole alarm
groups** (post-grouping), in contrast to the row-level Decision-Tree
classifier in ``ml/`` (pre-grouping). Mirrors the ``workshop/ml-baseline``
experiment.
"""

from otalon_clas.ml.group_classifier.classifier import GroupClassifier
from otalon_clas.ml.group_classifier.features import (
    extract_alarm_features,
    feature_names,
)
from otalon_clas.ml.group_classifier.labeler import GroupAlarmLabeler
from otalon_clas.ml.group_classifier.repository import \
    GroupClassifierTrainingRepository
from otalon_clas.ml.group_classifier.store import (GroupClassifierStore,
                                                          StoredGroupModel)
from otalon_clas.ml.group_classifier.trainer import (
    GroupClassifierTrainer, TrainResult)

__all__ = [
    "extract_alarm_features",
    "feature_names",
    "GroupAlarmLabeler",
    "GroupClassifier",
    "GroupClassifierStore",
    "GroupClassifierTrainer",
    "GroupClassifierTrainingRepository",
    "StoredGroupModel",
    "TrainResult",
]
