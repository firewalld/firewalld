import firewalld_client
import firewalld_error as err
import fw_services
import time

fw = firewalld_client.FirewallD_Client()

for i in xrange(10):
    for svc in fw_services.service_list:
        print svc.key

        status = fw.enableService(svc.key, 10)
        if status == err.ALREADY_ENABLED:
            continue
        if status != 0:
            print "%s: ENABLE FAILED: %d" % (svc.key, status)
            continue
        time.sleep(1)
        if fw.queryService(svc.key) != 1:
            print "-- %s NOT ENABLED --" % (svc.key)
        status = fw.disableService(svc.key)
        if status != 0 and status != err.NOT_ENABLED:
            print "%s: DISABLE FAILED: %d" % (svc.key, status)
        if fw.queryService(svc.key) != 0:
            print "-- %s NOT DISABLED --" % (svc.key)

