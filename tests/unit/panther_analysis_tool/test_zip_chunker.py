import unittest

from panther_analysis_tool.zip_chunker import (
    ChunkFiles,
    ZipChunk,
    create_additional_chunks_if_needed,
)


class TestZipChunks(unittest.TestCase):
    def test_shared_parents_matches(self) -> None:
        # tests that a single file can have multiple parents
        chunk = ChunkFiles(ZipChunk(patterns=["*"]))
        chunk.add_file("file1")
        chunk.add_file("shared_dep", "file1")
        chunk.add_file("file2")
        chunk.add_file("shared_dep", "file2")

        self.assertEqual(chunk.related_files, {"file1": "shared_dep", "file2": "shared_dep"})

    def test_additional_chunks_does_not_split_shared_files(self) -> None:
        # tests that a shared file is included in both chunks
        chunk = ChunkFiles(ZipChunk(patterns=["*"], max_size=1))
        chunk.add_file("file1")
        chunk.add_file("shared_dep", "file1")
        chunk.add_file("file2")
        chunk.add_file("shared_dep", "file2")

        chunks = create_additional_chunks_if_needed([chunk])

        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0].files, ["file1", "shared_dep"])
        self.assertEqual(chunks[1].files, ["file2", "shared_dep"])
