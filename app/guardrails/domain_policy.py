import numpy as np
import logging
from dataclasses import dataclass
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)


@dataclass
class PolicyResult:
    is_allowed: bool
    matched_topic: str | None
    similarity: float
    reason: str | None


class DomainPolicyValidator:
    def __init__(self, allowed_topics: list[str], threshold: float = 0.30):
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.threshold = threshold
        self.allowed_topics = allowed_topics
        self.topic_embeddings = self.model.encode(
            allowed_topics,
            normalize_embeddings=True
        )
        logger.info(
            f"Domain policy loaded with {len(allowed_topics)} topics, "
            f"threshold={threshold}"
        )

    def validate(self, query: str) -> PolicyResult:
        query_embedding = self.model.encode(query, normalize_embeddings=True)
        similarities = np.dot(self.topic_embeddings, query_embedding)
        best_idx = int(np.argmax(similarities))
        best_score = float(similarities[best_idx])
        best_topic = self.allowed_topics[best_idx]

        if best_score >= self.threshold:
            return PolicyResult(
                is_allowed=True,
                matched_topic=best_topic,
                similarity=round(best_score, 4),
                reason=None,
            )

        return PolicyResult(
            is_allowed=False,
            matched_topic=best_topic,
            similarity=round(best_score, 4),
            reason=(
                f"Query is off-topic. Closest match '{best_topic}' "
                f"at {round(best_score, 4)} below threshold {self.threshold}"
            ),
        )


def build_domain_policy(topics: list[str], threshold: float) -> DomainPolicyValidator:
    """Build a DomainPolicyValidator from config. Called at startup."""
    return DomainPolicyValidator(allowed_topics=topics, threshold=threshold)
