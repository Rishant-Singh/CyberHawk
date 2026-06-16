"""Elasticsearch service — log indexing, full-text search, aggregations."""

import logging
from datetime import datetime
from elasticsearch import AsyncElasticsearch
from core.config import settings

logger = logging.getLogger(__name__)

_es_client: AsyncElasticsearch | None = None


def get_es() -> AsyncElasticsearch:
    global _es_client
    if _es_client is None:
        _es_client = AsyncElasticsearch(
            [settings.ELASTICSEARCH_URL],
            request_timeout=30,
        )
    return _es_client


async def search_logs(
    query: str = None,
    src_ip: str = None,
    threat_level: str = None,
    start_time: datetime = None,
    end_time: datetime = None,
    min_score: int = None,
    page: int = 1,
    size: int = 50,
) -> dict:
    """Full-text search and filter logs from Elasticsearch."""
    es = get_es()
    must_clauses = []
    filter_clauses = []

    if query:
        must_clauses.append({
            "multi_match": {
                "query": query,
                "fields": ["src_ip", "dst_ip", "attack_type", "mitre_technique",
                           "classification", "geo_country", "explanation"],
            }
        })

    if src_ip:
        filter_clauses.append({"term": {"src_ip": src_ip}})

    if threat_level:
        filter_clauses.append({"term": {"threat_level": threat_level}})

    if min_score is not None:
        filter_clauses.append({"range": {"threat_score": {"gte": min_score}}})

    if start_time or end_time:
        time_range = {}
        if start_time:
            time_range["gte"] = start_time.isoformat()
        if end_time:
            time_range["lte"] = end_time.isoformat()
        filter_clauses.append({"range": {"timestamp": time_range}})

    body = {
        "query": {
            "bool": {
                "must": must_clauses or [{"match_all": {}}],
                "filter": filter_clauses,
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "from": (page - 1) * size,
        "size": size,
    }

    try:
        result = await es.search(
            index=f"{settings.ES_INDEX_THREATS},{settings.ES_INDEX_LOGS}",
            query=body["query"],
            sort=body["sort"],
            from_=(page - 1) * size,
            size=size,
        )
        hits = result["hits"]
        return {
            "total": hits["total"]["value"],
            "results": [h["_source"] for h in hits["hits"]],
        }
    except Exception as e:
        logger.error(f"Elasticsearch search failed: {e}")
        return {"total": 0, "results": []}


async def get_threat_heatmap(hours: int = 24) -> list[dict]:
    """Get hourly threat counts for heatmap visualization."""
    es = get_es()
    body = {
        "query": {
            "range": {
                "timestamp": {"gte": f"now-{hours}h"}
            }
        },
        "aggs": {
            "by_hour": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": "hour",
                },
                "aggs": {
                    "by_level": {
                        "terms": {"field": "threat_level", "size": 5}
                    }
                }
            }
        },
        "size": 0,
    }

    try:
        result = await es.search(
            index=settings.ES_INDEX_THREATS,
            query=body["query"],
            size=0,
            aggs=body["aggs"],
        )
        buckets = result["aggregations"]["by_hour"]["buckets"]
        return [
            {
                "hour": b["key_as_string"],
                "count": b["doc_count"],
                "by_level": {
                    lvl["key"]: lvl["doc_count"]
                    for lvl in b["by_level"]["buckets"]
                },
            }
            for b in buckets
        ]
    except Exception as e:
        logger.error(f"Heatmap aggregation failed: {e}")
        return []
