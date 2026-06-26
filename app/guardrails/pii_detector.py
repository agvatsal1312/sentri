from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from app.core.config import settings

class PIIDetector:
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.entities = [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "CRYPTO",
            "IBAN_CODE",
            "IP_ADDRESS",
            "PERSON",
            "LOCATION",
        ]

    def analyze(self, text: str) -> list:
        return self.analyzer.analyze(
            text=text,
            entities=self.entities,
            language="en"
        )

    def scrub(self, text: str) -> tuple[str, list]:
        results = self.analyze(text)
        if not results:
            return text, []

        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators={
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
                "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE>"}),
                "CREDIT_CARD": OperatorConfig("replace", {"new_value": "<CREDIT_CARD>"}),
                "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
                "LOCATION": OperatorConfig("replace", {"new_value": "<LOCATION>"}),
                "IP_ADDRESS": OperatorConfig("replace", {"new_value": "<IP>"}),
                "CRYPTO": OperatorConfig("replace", {"new_value": "<CRYPTO>"}),
                "IBAN_CODE": OperatorConfig("replace", {"new_value": "<IBAN>"}),
            }
        )

        detected = [{"type": r.entity_type, "score": round(r.score, 2)} for r in results]
        return anonymized.text, detected

    def has_pii(self, text: str) -> bool:
        return len(self.analyze(text)) > 0

# singleton
pii_detector = PIIDetector()