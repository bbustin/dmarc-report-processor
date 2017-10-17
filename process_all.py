#!/usr/bin/python
import glob
import dmarc_parser

class Args(object):
	pass

args = Args()
glob_pattern = '*.xml'
args.dmarcfile = glob.glob(glob_pattern)
args.outfile = 'processed.csv'

dmarc_parser.main(args)