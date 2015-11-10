#!/usr/bin/python

import pdb
import sys
import os.path
import traceback
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "python","/home/tom/nemea/nemea-install/share/nemea-python","/home/tom/nemea/nemea-install/","/home/tom/nemea/nemea-install/lib"))
import trap
import unirec
#from py2neo import Graph, Node, Relationship,authenticate
import networkx as nx
#import graph_tool.all as grt
from datetime import datetime
import time
import pylab as p
from thread import start_new_thread,allocate_lock
import  ipaddress

lock = allocate_lock() 
gr=nx.DiGraph()

time_window = 0
time_stats_window = 0
stats_interval = 0
newest_time = 0
src_ip = None
dst_ip = None
rec_time = None
properties = None
prop_array = None
option_dict = None
ip_range = None
allowed_properties = ["PORT","BYTES", "PACKETS", "DST_PORT", "SRC_PORT", "HTTP_RSP_CODE", "PROTOCOL", "TCP_FLAGS", "TTL", "TIME_FIRST", "TIME_LAST"]
incounter = 0
learning_interval = 3
is_learning = True


# How to add options of module
from optparse import OptionParser
parser = OptionParser(add_help_option=False)
parser.add_option("-p", "--properties",
         dest="properties",default=None,
         help="Set properties to be saved. Separated by comma. Its possible to choose from: "+str(allowed_properties))
parser.add_option("-r", "--ip-range",
         dest="ip_range",default=None,
         help="Set range of ip addresses in local network first ip-last ip ")
parser.add_option("-t", "--time-window",
         dest="time_window",default=60,
         help="Set size of time window for keeping data in seconds. Defalut is 60 sec.")
parser.add_option("-s", "--time-statistics-window",
         dest="time_stats_window",default=60,
         help="Set size of time window for for statistics processing interval. Defalut is 60 sec.")
parser.add_option("-e", "--export-interval",
         dest="export_interval",default=60,
         help="Set data export interval. Default is 60 sec.")
parser.add_option("-f", "--file", dest="filename",default=None,
         help="Set directory to save data. If parameter is not set, data are not saved.", metavar="FILE")
parser.add_option("-q", "--quiet",
         action="store_false", dest="verbose", default=True,
         help="don't print status messages to stdout")

#------------------------------------------------------


def DataProcess(stats_interval):
   addresses_used = set()
   addresses_added = set()
   edges_used = set()
   edges_added = set()
   edges_removed =set()
   addresses_removed = set()
   edge_new = set()
   addresses_new =set()
   addresses_last = set()
   edges_last = set()
   addresses_first_removed = set()
   edges_first_removed = set()
   addresses_past_removed =set()
   edges_past_removed =set()
   while True:
      lock.acquire()
      RemoveOldData()
      #print addresses_used
      #print gr.nodes()
      addresses_new = set(gr.nodes()).difference(addresses_used)
      addresses_added = set(gr.nodes()).difference(addresses_last)
      addresses_used.update(addresses_new)
      edges_new =  set(gr.edges()).difference(edges_used)
      edges_added = set(gr.edges()).difference(edges_last)
      edges_used.update(edges_new)
      addresses_removed = addresses_last.difference(set(gr.nodes()))
      addresses_first_removed = addresses_used.difference(addresses_past_removed).difference(set(gr.nodes()))
      addresses_past_removed.update(addresses_first_removed)
      edges_removed = edges_last.difference(set(gr.edges()))
      edges_first_removed = edges_used.difference(edges_past_removed).difference(set(gr.edges()))
      edges_past_removed.update(edges_first_removed)
      

      #print addresses_removed
      #print edges_removed
      #print "addresses first added", addresses_new
      #print "edges first added", edges_new
      #print "addr fst removed",addresses_first_removed
      #print "add removed", addresses_removed
      #for addr in addresses_used:
      #   CheckAddrExists(addr,is_learning)
      #for edge in edges_used:
      #   CheckEdgeExists(str(edge),is_learning)
      edges_last = set(gr.edges())
      addresses_last = set(gr.nodes())
      lock.release()   
      time.sleep(stats_interval)

#--------------------------------------------------------


def UpdateParameters(src_ip,dst_ip,rec,properties):
   for p in properties:
      p_cut = p.replace("_", "")
      str(getattr(rec,p))
      if p_cut in gr.edge[src_ip][dst_ip]:
         if not str(getattr(rec,p)) in gr.edge[src_ip][dst_ip][p_cut]:
            gr.edge[src_ip][dst_ip][p_cut][str(getattr(rec,p))] = 1
         else:
            gr.edge[src_ip][dst_ip][p_cut][str(getattr(rec,p))] = gr.edge[src_ip][dst_ip][p_cut][str(getattr(rec,p))] + 1
         
      else:
         gr.edge[src_ip][dst_ip][p_cut] = {}
         gr.edge[src_ip][dst_ip][p_cut][str(getattr(rec,p))] = 1
      #print gr.edge[src_ip][dst_ip][p_cut]
   return gr

def CheckIPRange(ip,ip_range):
   if ip_range is not None:
      if not any(ipaddress.ip_address(unicode(ip, "utf-8")) in p for p in ip_range):
         ip = "0.0.0.0"
         
      
   return ip


def AddRecord(rec, gr, properties,ip_range):

   src_ip = CheckIPRange(str(rec.SRC_IP),ip_range)
   dst_ip = CheckIPRange(str(rec.DST_IP),ip_range)
   
   #print src_ip,dst_ip 
   if src_ip != dst_ip:
      if gr.has_edge(src_ip,dst_ip):
         gr[src_ip][dst_ip]['weight'] += 1
         gr[src_ip][dst_ip]['time'] = rec.TIME_LAST.getSec()
         if properties is not None:
            gr = UpdateParameters(src_ip,dst_ip,rec,properties)
         
      else:
         gr.add_edge(src_ip,dst_ip, weight = 1, time = rec.TIME_LAST.getSec())
         if properties is not None:
            gr = UpdateParameters(src_ip,dst_ip,rec,properties)
   #print gr.edge[src_ip][dst_ip]['SRCPORT']
   return gr
      

def RemoveOldData():
   for edge in gr.edges_iter(data=True):
      if edge[2]['time'] < oldest_time:
         gr.remove_edge(edge[0],edge[1])
         n1 = nx.all_neighbors(gr, edge[0])
         n2 = nx.all_neighbors(gr, edge[1])
         if next(n1, "_empty") == "_empty":
            gr.remove_node(edge[0])
         if next(n2, "_empty") == "_empty":
            gr.remove_node(edge[1])


def ParseAdditionalParams(parser,ip_range, prop_array):
   options, args = parser.parse_args()
   option_dict = vars(options)
   properties = option_dict['properties']
   ip_range = option_dict['ip_range']
   if properties is not None:
      prop_array = properties.split(',')
   
   if ip_range is not None:
      ip_range = ip_range.split('-')
      ip_range = list(ipaddress.summarize_address_range(ipaddress.ip_address(unicode(ip_range[0], "utf-8")), ipaddress.ip_address(unicode(ip_range[1], "utf-8"))))
   

   return option_dict, prop_array,ip_range, int(option_dict['export_interval']), option_dict['filename'],int(option_dict['time_window']),int(option_dict['time_stats_window'])
   

def ExportProces(time_delta, directory):
   while True:
      lock.acquire()
      RemoveOldData()
      if directory is not None: 
         ExportData(time_delta,directory)
      lock.release()
      time.sleep(time_delta)


def ExportData(time_delta = 60, directory = "data"):
   print "exporting data"
   if not os.path.exists(directory):
      os.makedirs(directory)       
   nx.write_gml(gr, str(directory)+"/"+str(time.time()))
      




module_info = trap.CreateModuleInfo(
   "GraphFlow", # Module name
   "Graph representation of local network", # Description
   1, # Number of input interfaces
   0,  # Number of output interfaces
   parser # use previously defined OptionParser
)

# Initialize module
ifc_spec = trap.parseParams(sys.argv, module_info)

trap.init(module_info, ifc_spec)

trap.registerDefaultSignalHandler() # This is needed to allow module termination using s SIGINT or SIGTERM signal

# this module accepts all UniRec fieds -> set required format:
trap.set_required_fmt(0, trap.TRAP_FMT_UNIREC, "")

# Specifier of UniRec records will be received during libtrap negotiation
UR_Flow = None

option_dict, prop_array,ip_range, export_interval,filename, time_window, stats_interval = ParseAdditionalParams(parser,ip_range,prop_array)
try:
   start_new_thread(DataProcess,(stats_interval,))
   start_new_thread(ExportProces,(export_interval,filename))
except Exception:
   print traceback.format_exc()



# Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
while not trap.stop:
   # Read data from input interface
   try:
      data = trap.recv(0)
   except trap.EFMTMismatch:
      print("Error: output and input interfaces data format or data specifier mismatch")
      break
   except trap.EFMTChanged as e:
         # Get data format from negotiation
      (fmttype, fmtspec) = trap.get_data_fmt(trap.IFC_INPUT, 0)
      UR_Flow = unirec.CreateTemplate("UR_Flow", fmtspec)
      print("Negotiation:", fmttype, fmtspec)
      UR_Flow2 = unirec.CreateTemplate("UR_Flow2", fmtspec)
      print "Negotiation"
      # Set the same format for output IFC negotiation
      #trap.set_data_fmt(0, fmttype, fmtspec)
      data = e.data
   except trap.ETerminated:
      print "fmt exception"
      break

   # Check for "end-of-stream" record
   if len(data) <= 1:
      break

   
   rec = UR_Flow(data)
   
   if newest_time < rec.TIME_LAST.getSec():
      newest_time = rec.TIME_LAST.getSec()
   
   oldest_time = newest_time - time_window

   if incounter > learning_interval:
      is_learning = False

   lock.acquire()
   gr = AddRecord(rec, gr,prop_array, ip_range)
   lock.release()

   incounter+=1  
   



time.sleep(export_interval+1)
print gr.nodes()
print gr.edges() 
print incounter
#nx.draw_networkx(gr,with_labels=True)
#p.show()
  

