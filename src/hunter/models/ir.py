from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class IRNode(BaseModel):
    id: str
    kind: str
    label: str = ""
    file_rel_path: str
    start_byte: int
    end_byte: int
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    properties: dict[str, Any] = Field(default_factory=dict)


class IREdge(BaseModel):
    id: str
    src_id: str
    dst_id: str
    kind: str
    properties: dict[str, Any] = Field(default_factory=dict)


class CommentNode(BaseModel):
    id: str
    file_rel_path: str
    start_byte: int
    end_byte: int
    text_preview: str = ""
    attached_to_ir_id: str | None = None


class ParseDiagnostic(BaseModel):
    code: str
    message: str
    line: int | None = None


class FileParseArtifact(BaseModel):
    rel_path: str
    language: Literal["php", "javascript", "html", "other"]
    ir_nodes: list[IRNode] = Field(default_factory=list)
    ir_edges: list[IREdge] = Field(default_factory=list)
    comments: list[CommentNode] = Field(default_factory=list)
    diagnostics: list[ParseDiagnostic] = Field(default_factory=list)
    status: Literal["OK", "PARTIAL", "ERROR", "PARSE_CRASH"] = "OK"
    parser_lock_hash: str = ""


class ParseRunResult(BaseModel):
    per_file: dict[str, FileParseArtifact] = Field(default_factory=dict)
    parser_lock_hash: str = ""
