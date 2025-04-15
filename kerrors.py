#####################################################################################
#
# 	Name: kerrors.py
# 	Author: Rick R
# 	Purpose:  Error routines to support k-rest.py
#                      
#####################################################################################
import  json

def kPrintError(t_str, t_r):
# -----------------------------------------------------------------------------
# The objective is to print the error information back in the even that a HTTPS
# response is not STATUS_OK
# -----------------------------------------------------------------------------
    t_str_sc    = str(t_r.status_code)
    t_str_r     = str(t_r.reason)
    # t_str_e     = str(t_r.json()['error'])
    # t_str_e     = str(t_r.json())
    t_str_e     = str(t_r)
    
    tmpstr1      = "  --> %s " %(t_str)
    tmpstr2      = "Status Code: %s\n   Reason: %s\n   Error: %s" %(t_str_sc, t_str_r, t_str_e)
    
    print(tmpstr1, tmpstr2)

    return