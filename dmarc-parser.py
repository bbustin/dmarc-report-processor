#!/usr/bin/python
#
# Copyright (c) 2014, Yahoo! Inc.
# Copyrights licensed under the New BSD License. See the
# accompanying LICENSE.txt file for terms.
#
# Author Binu P. Ramakrishnan
# Created 09/12/2014
#
# Modified by Brian Bustin
#
# Program that accepts a (LARGE) xml file and converts it to 
# a CSV file
from __future__ import unicode_literals

import sys
import os
import xml.etree.cElementTree as etree
import argparse
import socket
import csv
import datetime
from collections import defaultdict

meta_fields = ['org_name', 'email', 'extra_contact_info', 'report_id', 'date_range/begin', 'date_range/end']
policy_fields = ['domain', 'adkim', 'aspf', 'p', 'pct']
record_fields = [
  'row/source_ip', 
  'row/count',
  'row/policy_evaluated/disposition',
  'row/policy_evaluated/dkim',
  'row/policy_evaluated/spf',
  'row/policy_evaluated/reason/type',
  'row/policy_evaluated/reason/comment',
  'identifiers/envelope_to',
  'identifiers/header_from',
  'auth_results/dkim/domain',
  'auth_results/dkim/result',
  'auth_results/dkim/human_result',
  'auth_results/spf/domain',
  'auth_results/spf/result',
]

class FieldNameCache(dict):
  '''
  "Caches" field names calculated from field sources
  '''
  # parts of the field names to exclude - used by convert_to_header
  header_exclusions = ['row', 'identifiers', 'auth_results']

  def __getitem__(self, field):
    result = None
    try:
      result = super(FieldNameCache, self).__getitem__(field)
    except KeyError as e:
      result = self._calculate_field_name(field)
      if result:
        super(FieldNameCache, self).__setitem__(field, result)
      else:
        raise e
    return(result)

  def _calculate_field_name(self, field):
    '''
    calculates field name from field source
    '''
    field_parts = field.split('/')
    header_parts = [part for part in field_parts if part not in self.header_exclusions]
    return "_".join(header_parts)

# caches mapping from field to header name to avoid having to call convert_to_header for every field every record
field_header_mapping = FieldNameCache()

# returns meta fields
def get_meta(context):
  report_meta = ""
  feedback_pub = ""

  pp = 0
  rm = 0  

  # get the root element
  event, root = context.next()
  for event, elem in context:
    if event == "end" and elem.tag == "report_metadata":
      # process record elements
      report_meta = {}

      for field in meta_fields:
        field_name = field_header_mapping[field]
        report_meta[field_name] = elem.findtext(field, 'NULL')

      rm = 1
      root.clear();
      continue

    if event == "end" and elem.tag == "policy_published":
      feedback_pub = {}

      for field in policy_fields:
        field_name = field_header_mapping[field]
        feedback_pub[field_name] = elem.findtext(field, 'NULL')

      pp = 1
      root.clear();
      continue      

    if pp == 1 and rm == 1:
      meta = report_meta.copy()
      meta.update(feedback_pub)

      # convert epoch times into more human-readable times
      field_names_to_update = [field_header_mapping['date_range/begin'], field_header_mapping['date_range/end']]
      for field in field_names_to_update:
        timestamp = float(meta[field])
        meta[field] = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")

      return meta
  return

# gets all field names and is used for writing the header
def get_all_field_names():
  '''
  Gets all field names and is used for passing all the field name values to the
  csv.DictWriter.

  The process of looking up each of the fields sources in
  field_header_mapping will effectively cache them in the field_header_mapping
  dictionary for the remainder of execution.
  '''
  field_names = []
  for field_type in [meta_fields, policy_fields, record_fields]:
    field_names.extend([field_header_mapping[field] for field in field_type])
  return field_names


def write_records(csv_dict_writer, context, meta):

  # get the root element
  event, root = context.next();

  for event, elem in context:
    if event == "end" and elem.tag == "record":
      record = {}
      # process record elements
      # NOTE: This may require additional input validation
      for field in record_fields:
        field_name = field_header_mapping[field]
        record[field_name] = elem.findtext(field, 'NULL')

      # try:
      #   record['x_host_name'] = socket.getfqdn(source_ip)
      # except:
      #   record['x_host_name'] = None

      record.update(meta) #add report metadata to record
      csv_dict_writer.writerow(record)
      root.clear()
      continue
  return

def generate_csv_file_name(args):
  '''
  Calculates csv file name based on name of dmarcfile
  '''
  file_name = "{}.csv".format(".".join(args.dmarcfile[0].split('.')[:-1]))
  return file_name

def main():
  global args
  options = argparse.ArgumentParser(epilog="Example: \
%(prog)s dmarc-xml-file 1> outfile.log")
  options.add_argument("dmarcfile", help="dmarc file(s) in XML format", nargs="+")
  options.add_argument("--outfile", help="name of output CSV file")
  args = options.parse_args()

  if not args.outfile:
    if len(args.dmarcfile) == 1:
      args.outfile = generate_csv_file_name(args)
    else:
      raise Exception("--outfile must be set if more than 1 dmarcfile to be processed")

  with open(args.outfile, 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=get_all_field_names())
    writer.writeheader()

    for dmarcfile in args.dmarcfile:
      print("processing {}".format(dmarcfile))
      meta_fields = get_meta(iter(etree.iterparse(dmarcfile, events=(b"start", b"end"))));
      if not meta_fields:
        print >> sys.stderr, "Error: No valid 'policy_published' and 'report_metadata' xml tags found; File: " + args.dmarcfile 
        sys.exit(1)
      write_records(writer, iter(etree.iterparse(dmarcfile, events=(b"start", b"end"))), meta_fields)

if __name__ == "__main__":
  main()

