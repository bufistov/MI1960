from kazoo.client import KazooClient
from kazoo.exceptions import NodeExistsError

import logging
import json
import argparse
import os.path
import sys

from keystoneauth1 import identity
from keystoneauth1 import session
from neutronclient.v2_0 import client

logging.basicConfig()

neutron_zkpath = '/midonet/v1/neutron'
sg_container_path = neutron_zkpath + '/security_groups'
sgr_container_path = neutron_zkpath + '/security_group_rules'

verbose = False
exit_code = 0

def parse_args():
    parser = argparse.ArgumentParser(description="Remove unreferenced 'security_group_rules' entries from Zookeeper (Midonet 1.9.10)")
    group = parser.add_mutually_exclusive_group()
    parser.add_argument('--zookeeper-address', action='store', metavar='HOST:PORT', required=True,
                       help='host and port of Zookeeper service')
    parser.add_argument('--backup-file', action='store', metavar='FILE', required=True,
                       help='backup file')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='verbose mode')
    group.add_argument('--backup-garbage', action='store_true',
                       help='backup garbage entries (default)')
    group.add_argument('--backup-and-remove-garbage', action='store_true',
                       help='backup garbage entries and remove them')
    group.add_argument('--verify-backup', action='store_true',
                       help='verify that all entries from a backup file could be restored')
    group.add_argument('--restore-backup', action='store_true',
                       help='restore all entries from a backup file')
    args = parser.parse_args()
    verbose = args.verbose
    debug('Input arguments')
    debug(args)
    return args

def find_garbage(zk, neutron, backup, remove_garbage):

    count = 0

    referenced_sgr_ids = dict()

    debug('Finding garbage(1/2): looking for security groups rules in Neutron...')

    sgs = neutron.list_security_groups()
    for sg in sgs['security_groups']:
        sg_id = str(sg['id'])
        debug('    security group: ' + sg_id)
        for sgr in sg['security_group_rules']:
            sgr_id = str(sgr['id'])
            debug('        security group rule: ' + sgr_id)
            referenced_sgr_ids[sgr_id] = sg_id

    debug('Finding gargabe (2/2): looking for orphan security group rules in Zookeeper...')
 
    sgr_list = zk.get_children(sgr_container_path)
    for sgr_id in sgr_list:
        sgr_zkpath = sgr_container_path + '/' + sgr_id
        if sgr_id in referenced_sgr_ids:
            sg_id = referenced_sgr_ids[sgr_id]
            sg_zkpath = sg_container_path + '/' + sg_id
            debug(sgr_zkpath + ' referenced by ' + sg_zkpath)
        else:
            # not referenced -> is garbage

            # write to backup file
            sgr_data, stat = zk.get(sgr_zkpath)
            backup.write('%s%s' % (sgr_data.strip(),'\n'))

            # check options to see if garbage needs to be removed
            if remove_garbage:
                print(sgr_zkpath + ' not referenced -> REMOVING')
                zk.delete(sgr_zkpath)
                print(sgr_zkpath + ' not referenced -> REMOVED')
            else:
                print(sgr_zkpath + ' not referenced -> SHOULD BE REMOVED (use --backup-and-remove-garbage option)')
            count += 1

    if(remove_garbage):
        print('Removed ' + str(count) + ' garbage entries')
    else:
        print('Found ' + str(count) + ' garbage entries. Use --backup-and-remove-garbage option and a new backup file name to remove them')

def verify_backup(zk, backup):
    global exit_code
    count = 0
    count_verified = 0
    debug('Verifying backup')
    for line in backup:
       if line.strip():
	   count += 1
           try:
	       sgr_data_as_json = json.loads(line)
           except:
               print('ERROR: cannot parse json object %s' % line)
               exit_code=1

	   sgr_id = sgr_data_as_json['data']['id']
	   sgr_zkpath = sgr_container_path + '/' + sgr_id
	   if not zk.exists(sgr_zkpath):
	       count_verified += 1
	   else:
	       print('WARNING: node in backup already exists: ' + sgr_zkpath)
	       exit_code = 1
    print('Verified ' + str(count_verified) + '/' + str(count) + ' entries could be restored')

def restore_backup(zk, backup):
    global exit_code
    count = 0
    count_restored = 0
    debug('Restoring backup')
    for line in backup:
       if line.strip():
	   count += 1
	   sgr_data_as_json = json.loads(line)
	   sgr_id = sgr_data_as_json['data']['id']
	   sgr_zkpath = sgr_container_path + '/' + sgr_id
	   try:
	       zk.create(sgr_zkpath, line)
	       count_restored += 1
	   except NodeExistsError:
	       print('ERROR: cannot create ' + sgr_zkpath +'. Node already exists')
	       exit_code = 1
    print('Restored ' + str(count_restored) + '/' + str(count) + ' entries')

def check_schema_version_or_die(zk):
    schemaVersion = 4
    schema_zkpath = '/midonet/v1/config/schemas/nsdb'

    data, stat = zk.get(schema_zkpath)
    for line in data.splitlines():
        if line.strip() == 'schemaVersion=' + str(schemaVersion):
            return 
    print('Invalid schema version: schemaVersion=' + str(schemaVersion) + ' not found in ' + schema_zkpath + ' entry of Zookeeper')
    exit(1)

def debug(msg):
    if verbose:
        print(msg)

def get_credentials():
    d = {}
    d['username'] = os.environ['OS_USERNAME']
    d['password'] = os.environ['OS_PASSWORD']
    d['auth_url'] = os.environ['OS_AUTH_URL']
    d['tenant_name'] = os.environ['OS_TENANT_NAME']
    return d

def get_neutron_client_with_credentials(username,
                                        password,
                                        project_name,
                                        project_domain_id,
                                        user_domain_id,
                                        auth_url):
    print('Connecting to neutron')
        
    auth = identity.Password(auth_url=auth_url,
                             username=username,
                             password=password,
                             project_name=project_name,
                             project_domain_id=project_domain_id,
                             user_domain_id=user_domain_id)
    sess = session.Session(auth=auth)
    neutron = client.Client(session=sess)
    neutron.list_networks()
    print('Connection to neutron completed')
    return neutron    

def get_neutron_client():
    credentials = get_credentials()
    return get_neutron_client_with_credentials(
                              credentials['username'],
                              credentials['password'],
                              credentials['tenant_name'],
                              None,
                              None,
                              credentials['auth_url'])

def main(args):
    zk = KazooClient(hosts=args.zookeeper_address, read_only=True)
    neutron = get_neutron_client()

    try:
	zk.start()
	debug('Connected to ' + args.zookeeper_address)

        check_schema_version_or_die(zk)

	if args.restore_backup or args.verify_backup:
	    with open(args.backup_file, "r") as f:
		if args.restore_backup: 
		    restore_backup(zk, f)
		else:
		    verify_backup(zk, f)
	else:
            if os.path.isfile(args.backup_file):
                print('Backup file exists and it would be overwritten, aborting')
                exit(2)
	    with open(args.backup_file, "w") as f:
		find_garbage(zk, neutron, f, args.backup_and_remove_garbage)
            print('Created backup file at: ' + args.backup_file)
    finally:
        debug('Disconnected from ' + args.zookeeper_address)
	zk.stop()

if __name__ == "__main__":
     args = parse_args()
     verbose = args.verbose
     debug('Input arguments')
     debug(args)
     main(args)
     exit(exit_code)

