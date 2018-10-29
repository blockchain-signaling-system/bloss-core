from collections import defaultdict
from datetime import datetime

from utils import safedivision


class Flow(object):
    def __init__(self, source=None, destination=None, byte_count=0):
        self._last_byte_count_write = datetime.now()
        self._source = self.source = source
        self._destination = self.destination = destination
        self._byte_count = self.byte_count = byte_count
        self._mbps = self.mbps = 0

    def __hash__(self):
        return hash((self.source, self.destination))

    def __eq__(self, other):
        return (self.source == other.source and
                self.destination == other.destination)

    def __ne__(self, other):
        return not self.__eq__(other)

    def _bytes_to_mbps(self, bytes):
        return safedivision(
            (bytes / 1024.0 / 1024.0) * 8,
            (datetime.now() - self._last_byte_count_write).seconds
        )

    @staticmethod
    def clamp(value, minimum, maximum):
        return max(min(maximum, value), minimum)

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value):
        self._source = value

    @property
    def destination(self):
        return self._destination

    @destination.setter
    def destination(self, value):
        self._destination = value

    @property
    def byte_count(self):
        return self._byte_count

    @byte_count.setter
    def byte_count(self, value):
        delta_byte_count = value - self._byte_count
        self.mbps = self._bytes_to_mbps(delta_byte_count)
        self.mbps = self.clamp(self.mbps, 0.0, 100.0)
        self._byte_count = value
        self._last_byte_count_write = datetime.now()

    @property
    def mbps(self):
        return self._mbps

    @mbps.setter
    def mbps(self, value):
        self._mbps = value


class FlowStatistics:
    def __init__(self):
        self._datapaths = defaultdict(lambda: list())

    def get_flow(self, datapath_id, source, destination):
        flow = Flow(source, destination)
        datapath = self._datapaths[datapath_id]
        if flow in datapath:
            return datapath[datapath.index(flow)]
        else:
            return self._add_flow(datapath_id, source, destination, 0)

    def get_flows(self, datapath_id):
        return self._datapaths[datapath_id]

    def _add_flow(self, datapath_id, source, destination, byte_count):
        flow = Flow(source, destination, byte_count)
        self._datapaths[datapath_id].append(flow)
        return flow


class FlowStatisticsManager:
    def __init__(self, config):
        self._flow_statistics = FlowStatistics()
        self._config = config

    def update_traffic_per_flow(self, datapath_id, statistics):
        for statistic in statistics:
            try:
                flow = (self._flow_statistics
                        .get_flow(datapath_id,
                                  statistic.match['ipv4_src'],
                                  statistic.match['ipv4_dst']))
            except Exception as e:
                continue

            flow.byte_count = statistic.byte_count

    def get_flows(self, datapath_id):
        return self._flow_statistics.get_flows(datapath_id)


def main():
    pass


if __name__ == "__main__":
    main()
