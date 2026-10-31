from django.core.management.base import BaseCommand

from accounts.models import AuditLog

from security_ai.features import (
    extract_features,
    features_to_vector,
)

from security_ai.model import model_manager

from security_ai.config import MIN_SAMPLES_FOR_TRAINING


class Command(BaseCommand):

    help = "Train the Security AI Isolation Forest model"

    def handle(self, *args, **options):

        self.stdout.write(
            self.style.WARNING(
                "Collecting audit logs..."
            )
        )

        logs = (
            AuditLog.objects
            .select_related("user")
            .order_by("created_at")
        )

        training_data = []

        for log in logs:

            # Prefer normal historical behaviour for training.
            if log.suspicious:
                continue

            features = extract_features(
                user=log.user,
                ip_address=log.ip_address,
                as_of_time=log.created_at,
                exclude_log_id=log.id,
            )

            vector = features_to_vector(features)

            training_data.append(vector)

        sample_count = len(training_data)

        self.stdout.write(
            f"Training samples found: {sample_count}"
        )

        if sample_count < MIN_SAMPLES_FOR_TRAINING:

            self.stdout.write(
                self.style.ERROR(
                    f"Not enough training samples. "
                    f"Minimum required: "
                    f"{MIN_SAMPLES_FOR_TRAINING}"
                )
            )

            return

        metadata = model_manager.train(
            training_data,
            version="1.0"
        )

        self.stdout.write(
            self.style.SUCCESS(
                "Security AI model trained successfully."
            )
        )

        self.stdout.write(
            f"Samples: {metadata['sample_count']}"
        )

        self.stdout.write(
            f"Features: {metadata['feature_count']}"
        )

        self.stdout.write(
            f"Detected training anomalies: "
            f"{metadata['train_anomalies_detected']}"
        )

        self.stdout.write(
            f"Version: {metadata['version']}"
        )