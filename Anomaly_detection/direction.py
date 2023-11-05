import ipaddress


def traffic_direction(conn_row):
    # First try to use the local orig/resp fields
#     if conn_row.get('local_orig') and conn_row.get('local_resp'):
#         local_orig = conn_row['local_orig']
#         local_resp = conn_row['local_resp']
#     else:
        # Well we don't have local orig/resp fields so use RFC1918 logic
    local_orig = ipaddress.ip_address(conn_row['id.orig_h']).is_private
    local_resp = ipaddress.ip_address(conn_row['id.resp_h']).is_private

    # Determine north/south or internal traffic
    if (not local_orig) and local_resp:
        return 'incoming'
    if local_orig and not local_resp:
        return 'outgoing'

    # Neither host is in the allocated private ranges
    if ipaddress.ip_address(conn_row['id.orig_h']).is_multicast or \
       ipaddress.ip_address(conn_row['id.resp_h']).is_multicast:
        return 'multicast'

    # Both hosts are internal
    return 'internal'