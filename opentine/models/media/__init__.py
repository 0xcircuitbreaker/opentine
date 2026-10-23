"""Media endpoints: image generation, text-to-speech and transcription.

Unlike the chat adapters these are one-shot calls with binary outputs. Each
returns a :class:`MediaResult` carrying media usage priced by the catalog's
per-image, per-character and per-minute cards; :meth:`MediaResult.record` adds it
to a run as a model step that ``tine price`` re-prices like any other.
"""

from opentine.models.media import openai_media, xai_media
from opentine.models.media._http import MediaError
from opentine.models.media._result import MediaOutput, MediaResult

__all__ = ["MediaError", "MediaOutput", "MediaResult", "openai_media", "xai_media"]
