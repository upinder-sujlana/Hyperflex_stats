### Hyperflex_stats

```
The HX_Performance_stats.py file is part of a ongoing project I am creating to grab data
out of hyperflex cluster using REST API. The script can be run to grab (at the moment) the
most critical information for diagnosing a cluster objects:-

++ OS type.
++ Server types and serial numbers.
++ HXDP version.
++ Cluster name, AF cluster or not, replication factor, # of nodes in the cluster and online and cluster policy.
++ SCVM UUID, disks per scvm, eth1 IP & CRM master or not.
++ Datastore name, size, free capacity, mount status, mount status per host.
++ Cluster UUID, total/used/free capacity, dedup & compression savings, storage state.

You can run the script using "admin" or vCenter credentials. Additionally ensure your
python installation has "requests" package installed (pip install requests).

```
