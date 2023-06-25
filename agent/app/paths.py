import os
from base_agent.paths import BasePaths

class LibFuzzerPaths(BasePaths):

    # fuzz
    @property
    def initial_corpus(self):
        return os.path.join(self.disk_volume, "initial_corpus")

    @property
    def result_corpus(self):
        return os.path.join(self.tmpfs_volume, "result_corpus")

    # merge
    @property
    def unmerged_corpus(self):
        return os.path.join(self.disk_volume, "unmerged_corpus")

    @property
    def merged_corpus(self):
        return os.path.join(self.tmpfs_volume, "merged_corpus") # TODO: maybe disk is fine?
    
    @property
    def merge_control_file(self):
        return os.path.join(self.tmpfs_volume, "merge_control_file.txt") # TODO: maybe disk is fine?
