from django.db import models


class BaseModel(models.Model):
    """Base model."""

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Meta option."""

        abstract = True

        ordering = ["-created_at", "-updated_at"]
