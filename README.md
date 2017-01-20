# MI1960
A python script to clean up zookeeper

Help is provided with the -h option, but I will comment here some extra info 
about usage.  First check that Python is installed and the Kazoo library to 
access zookeeper, for example:

```
pip install kazoo
```

The Zookeeper host and port (by default 2181) must be provided,
so the script can connect to a Zookeeper node.
First, dry run to check everything and create an initial backup of entries 
that could be removed. Before running check that enough disk space is available 
(NOTE: this backup is not a whole Zookeeper backup, so a normal backup of 
Zookeeper should be done as recommended by Midonet administrator guide, 
if applicable)

```
$ python midonet_1_9_10_clean_orphan_security_group_rules_from_zookeeper.py --zookeeper-address localhost:2181 --backup-file dry_run.backup --backup-garbage
```

Remove all the garbage (a different backup file will be generated, so a new
backup file name is needed)

```
$ python midonet_1_9_10_clean_orphan_security_group_rules_from_zookeeper.py --zookeeper-address localhost:2181 --backup-file removed.backup --backup-and-remove-garbage
```

The backup file should be kept until confirmed everything is ok.  This should be
 enough to fix the problem.  If any problem is detected, the backup file can be 
used to restore all the removed entries (use with caution).  First verify that 
there is no entries that overlap with the previous ones:

```
$ python midonet_1_9_10_clean_orphan_security_group_rules_from_zookeeper.py --zookeeper-address localhost:2181 --backup-file removed.backup --verify-backup
```
If everything is ok, the backup can be restored:

```
$ python midonet_1_9_10_clean_orphan_security_group_rules_from_zookeeper.py --zookeeper-address localhost:2181 --backup-file removed.backup --restored-backup
```
