import argparse
import os
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, Dict, List, Set

from panther_analysis_tool.analysis_utils import (
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
        try:
            filters = args.filter
        except:  # pylint: disable=bare-except # nosec
            pass

        try:
            filters_inverted = args.filter_inverted
        except:  # pylint: disable=bare-except # nosec
            pass
        return cls(
            out=args.out,
            path=args.path,
            ignore_files=args.ignore_files,
            filters=filters,  # type: ignore
            filters_inverted=filters_inverted,
        )


class ChunkFiles:
    chunk: ZipChunk
    files: List[str]
    added_files: Dict[str, bool]

    def __init__(self, chunk: ZipChunk):
        self.chunk = chunk
        self.files = []
        self.added_files = {}

    def add_file(self, filename: str) -> None:
        if self.added_files.get(filename) is None:
            self.added_files[filename] = True
            self.files.append(filename)

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


def analysis_chunks(args: ZipArgs, chunks: List[ZipChunk] = None) -> List[ChunkFiles]:
    """Generates all files that should be added to a zip file. If no chunks are provided
    a single chunk will be returned. Note: a file can be in multiple chunks if both chunks
    matches the file pattern
    :param args:
    :param chunks:
    :return:
    """

    if chunks is None or len(chunks) == 0:
        chunks = [ZipChunk(patterns=["*"])]

    chunk_files = [ChunkFiles(f) for f in chunks]
    analysis = []
    files: Set[str] = set()

    for (file_name, f_path, spec, _) in list(
        load_analysis_specs([args.path, HELPERS_LOCATION, DATA_MODEL_LOCATION], args.ignore_files)
    ):
        if file_name not in files:
            analysis.append((file_name, f_path, spec))
            files.add(file_name)
            files.add("./" + file_name)
    analysis = filter_analysis(analysis, args.filters, args.filters_inverted)
    for analysis_spec_filename, dir_name, analysis_spec in analysis:
        for chunk in chunk_files:
            if chunk.matches_file(analysis_spec_filename, analysis_spec):
                chunk.add_file(to_relative_path(analysis_spec_filename))
                # datamodels may not have python body
                if "Filename" in analysis_spec:
                    chunk.add_file(
                        to_relative_path(os.path.join(dir_name, analysis_spec["Filename"]))
                    )

    return chunk_files
