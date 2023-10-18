import argparse
import os
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, Dict, Generator, List, Optional, Set

from panther_analysis_tool.analysis_utils import (
    ClassifiedAnalysis,
    filter_analysis,
    load_analysis_specs,
    to_relative_path,
)
from panther_analysis_tool.constants import DATA_MODEL_LOCATION, HELPERS_LOCATION


@dataclass
class ZipChunk:
    """
    ZipChunk allows you to select which files should go into a given chunk
      - you can set patterns and types; this will match both cases
      - you can set patterns or types; this will match whichever value is set


    Patterns are Unix shell style:

        *       matches everything
        ?       matches any single character
        [seq]   matches any character in seq
        [!seq]  matches any char not in seq

        Note: if a pattern such as */folder is used ./folder/hey.txt will not match
        You will need a pattern that does */folder/* to match

    Types are the types we expect in AnalysisType of a given yaml
    """

    patterns: List[str]
    types: Set[str] = ()  # type: ignore
    max_size: Optional[int] = None

    @classmethod
    def from_patterns(cls, patterns: List[str]) -> Any:
        return cls(patterns=patterns)


@dataclass
class ZipArgs:
    out: Any
    path: Any
    ignore_files: List[str]
    filters: Dict[str, List]
    filters_inverted: Dict[str, List]

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> Any:
        filters = []
        filters_inverted = {}
        out = "./"
        try:
            filters = args.filter
        except:  # pylint: disable=bare-except # nosec
            pass

        try:
            filters_inverted = args.filter_inverted
        except:  # pylint: disable=bare-except # nosec
            pass

        try:
            out = args.out
        except:  # pylint: disable=bare-except # nosec
            pass
        return cls(
            out=out,
            path=args.path,
            ignore_files=args.ignore_files,
            filters=filters,  # type: ignore
            filters_inverted=filters_inverted,
        )


def chunk_list(lst: List[Any], limit: int) -> Generator[List[Any], None, None]:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), limit):
        yield lst[i : i + limit]


class ChunkFiles:
    chunk: ZipChunk
    files: List[str]
    primary_files: List[str]
    related_files: Dict[str, str]
    added_files: Dict[str, bool]

    def __init__(self, chunk: ZipChunk):
        self.chunk = chunk
        self.files = []
        self.primary_files = []
        self.related_files = {}
        self.added_files = {}

    def add_file(self, filename: str, parent: Optional[str] = None) -> None:
        if self.added_files.get(filename) is None:
            self.added_files[filename] = True
            self.files.append(filename)
            if parent is None:
                self.primary_files.append(filename)
            else:
                self.related_files[parent] = filename

    def can_chunk_further(self) -> bool:
        if self.chunk.max_size is None:
            return False
        return len(self.added_files) > self.chunk.max_size

    def matches_file(self, filename: str, spec: Dict[str, Any] = None) -> bool:
        if len(self.chunk.types) > 0 and spec is not None and "AnalysisType" in spec:
            if spec["AnalysisType"] not in self.chunk.types:
                return False

            if len(self.chunk.patterns) == 0:
                return True

        for pattern in self.chunk.patterns:
            if fnmatch(filename, pattern):
                return True

        return False


def create_additional_chunks_if_needed(chunk_files: List[ChunkFiles]) -> List[ChunkFiles]:
    results: List[ChunkFiles] = []
    for chunked in chunk_files:
        if not chunked.can_chunk_further():
            results.append(chunked)
            continue
        for files in chunk_list(chunked.primary_files, chunked.chunk.max_size):  # type: ignore
            chunk = ChunkFiles(chunk=chunked.chunk)
            for file in files:
                chunk.add_file(file)
                related_file = chunked.related_files.get(file)
                if related_file is not None:
                    chunk.add_file(related_file)
            results.append(chunk)
    return results


def analysis_chunks(args: ZipArgs, chunks: List[ZipChunk] = None) -> List[ChunkFiles]:
    """Generates all files that should be added to a zip file. If no chunks are provided
    a single chunk will be returned. Note: a file can be in multiple chunks if both chunks
    matches the file pattern
    :param args:
    :param chunks:
    :return:
    """
    analysis = analysis_for_chunks(args)
    return chunk_analysis(analysis, chunks)


def analysis_for_chunks(args: ZipArgs, no_helpers: bool = False) -> List[ClassifiedAnalysis]:
    analysis = []
    files: Set[str] = set()

    paths = [args.path]
    if not no_helpers:
        paths.extend([HELPERS_LOCATION, DATA_MODEL_LOCATION])
    for file_name, f_path, spec, _ in list(load_analysis_specs(paths, args.ignore_files)):
        if file_name not in files:
            analysis.append(ClassifiedAnalysis(file_name, f_path, spec))
            files.add(file_name)
            files.add("./" + file_name)
    return filter_analysis(analysis, args.filters, args.filters_inverted)


def chunk_analysis(
    analysis: List[ClassifiedAnalysis], chunks: List[ZipChunk] = None
) -> List[ChunkFiles]:
    if chunks is None or len(chunks) == 0:
        chunks = [ZipChunk(patterns=["*"])]
    chunk_files = [ChunkFiles(f) for f in chunks]
    for item in analysis:
        analysis_spec_filename = item.file_name
        dir_name = item.dir_name
        analysis_spec = item.analysis_spec
        main_file = to_relative_path(analysis_spec_filename)
        for chunk in chunk_files:
            if chunk.matches_file(analysis_spec_filename, analysis_spec):
                chunk.add_file(main_file)
                if analysis_spec is not None and "Filename" in analysis_spec:
                    chunk.add_file(
                        to_relative_path(os.path.join(dir_name, analysis_spec["Filename"])),
                        parent=main_file,
                    )
    return create_additional_chunks_if_needed(chunk_files)
