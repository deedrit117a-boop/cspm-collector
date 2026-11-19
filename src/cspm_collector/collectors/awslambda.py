"""Lambda: environment variables are masked, pre-signed code URLs are dropped."""
from __future__ import annotations

from cspm_collector.core.secrets import MASK, mask_environment
from cspm_collector.spec.schema import ApiSpec

from .base import register
from .generic import Entry, GenericCollector


@register("lambda")
class LambdaCollector(GenericCollector):
    def _mask_env(self, config: dict, entry: Entry) -> None:
        env = config.get("Environment")
        if isinstance(env, dict) and env.get("Variables"):
            env["Variables"], hits = mask_environment(env["Variables"], f"lambda.{entry.rid}.Environment")
            entry.findings += hits

    def sanitize_item(self, root: ApiSpec, entry: Entry) -> None:
        if root.api == "list_functions":
            self._mask_env(entry.item, entry)

    def sanitize_detail(self, api: ApiSpec, value, entry: Entry):
        if api.api == "get_function" and value:
            self._mask_env(value.get("Configuration") or {}, entry)
            code = value.get("Code")
            if isinstance(code, dict) and code.get("Location"):
                code["Location"] = MASK  # pre-signed download URL: a bearer credential for the code package
        return value

    def tags_for(self, root: ApiSpec, entry: Entry):
        return (entry.details.get("get_function") or {}).get("Tags")
