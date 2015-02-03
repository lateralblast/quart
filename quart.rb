#!/usr/bin/env ruby

# Name:         quart (QUalysguard Analysis Report Tool)
# Version:      0.2.3
# Release:      1
# License:      CC-BA (Creative Commons By Attribution)
#               http://creativecommons.org/licenses/by/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          http://lateralblast.com.au/
# Distribution: UNIX
# Vendor:       Lateral Blast
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  A Tool to process QualysGuardEnterprise Suite Vulnerability Scan PDF reports
#               

require 'rubygems'
require 'pdf-reader'
require 'getopt/long'
require 'writeexcel'

$script = $0
$text   = []

# Print script usage information

def print_usage()
  switches     = []
  long_switch  = ""
  short_switch = ""
  help_info    = ""
  puts ""
  puts "Usage: "+$script
  puts ""
  file_array  = IO.readlines $0
  option_list = file_array.grep(/\[ "--/)
  option_list.each do |line|
    if !line.match(/file_array/)
      help_info    = line.split(/# /)[1]
      switches     = line.split(/,/)
      long_switch  = switches[0].gsub(/\[/,"").gsub(/\s+/,"")
      short_switch = switches[1].gsub(/\s+/,"")
      if long_switch.gsub(/\s+/,"").length < 7
        puts long_switch+",\t\t"+short_switch+"\t"+help_info
      else
        puts long_switch+",\t"+short_switch+"\t"+help_info
      end
    end
  end
  puts
  return
end

# Get version

def get_version()
  file_array = IO.readlines $0
  version    = file_array.grep(/^# Version/)[0].split(":")[1].gsub(/^\s+/,'').chomp
  packager   = file_array.grep(/^# Packager/)[0].split(":")[1].gsub(/^\s+/,'').chomp
  name       = file_array.grep(/^# Name/)[0].split(":")[1].gsub(/^\s+/,'').chomp
  return version,packager,name
end

# Print script version information

def print_version()
  (version,packager,name) = get_version()
  puts name+" v. "+version+" "+packager
  exit
end

class TextReceiver
  # show text takes a string, but may have some other params for us to look through
  def show_text(string, *params)
    $text.push(string)
  end
  def show_text_with_positioning(array, *params)
    # make use of the show text method we already have
    # assuming we don't care about positioning right now and just want the text
    show_text(array.select{|i| i.is_a?(String)}.join(""), params)
  end
end

# Process PDF file

def process_pdf(input_file,output_file,vuln_array,headers,dump_data,mask_data)
  receiver   = TextReceiver.new
  reader     = PDF::Reader.new(input_file)
  host_name  = ""
  counter    = 0
  lines      = []
  pages      = []
  host_list  = []
  info_name  = ""
  info_data  = []
  vuln_name  = ""
  headers.push("Vulnerability")
  headers.push("Hosts")
  headers.push("Port")
  headers.push("CVSS")
  if output_file.match(/[A-z]|[0-9]/) and dump_data == 1
    file = File.open(output_file,"w")
  end
  reader.pages.each do |page|
    $text = []
    page.walk(receiver)
    pages.push($text)
  end
  lines  = pages.join("\n").split("\n")
  length = lines.length
  lines.each_with_index do |line, index|
    line = line.chomp
    if dump_data == 1
      if !line.match(/^Linux Vuln Scan Results|^page [0-9]/)
        if output_file.match(/[A-z]|[0-9]/)
          line = line+"\n"
          file.write(line)
        else
          puts line
        end
      end
    else
      if !line.match(/^Linux Vuln Scan Results|^page [0-9]/) and line.match(/[A-z]|[0-9]/)
        case line
        when /\)$/
          if line.match(/^[0-9]/) and !line.match(/GMT|3DES|Avg|[0-9] bit|[A-Z,2,4]\([0-9]/)
            host_name = line.split(/\,/)[0].split(/\(/)[1]
            if mask_data == 1
              host_name = host_name.gsub(/[a-z]/,[*('a'..'z')].sample)
            end
            host_list.push(host_name)
          else
            if line.match(/^[A-Z]/) and line.match(/[0-9]\)$/) and !line.match(/\=|\-|GMT|3DES|Avg|[0-9] bit|[A-Z,2,4]\([0-9]/) 
              vuln_array[vuln_name]["Hosts"]   = host_list.join("\n")
              host_list = []
              vuln_array[vuln_name][info_name] = info_data.join("\n")
              info_data = []
              vuln_name = line.split(/\(/)[0].gsub(/\s+$/,"")
            else
              if vuln_name.match(/[A-z]/)
                if mask_data == 1
                  case info_name
                  when /Asset Group/
                    line = "Masked"
                  end
                  case line
                  when /:[0-9,a-f][0-9,a-f]:[0-9,a-f][0-9,a-f]:/
                    info_data.push(line.gsub(/[0-9,a-f]/,"x"))
                  else
                    info_data.push(line)
                  end
                else
                  info_data.push(line)
                end
              end
            end
          end
        when /^port/
          if vuln_name.match(/[A-z]/)
            if line.match(/over/)
              vuln_array[vuln_name]["Port"] = line.split(/ /)[1..3].join(" ")
            else
              vuln_array[vuln_name]["Port"] = line.split(/ /)[1]
            end
            vuln_array[vuln_name]["Status"] = lines[index+1] 
          end
        when /CVSS: /
          if vuln_name.match(/[A-z]/)
            vuln_array[vuln_name]["CVSS"] = line.split(/CVSS: /)[1]
          end
        when /^ \-/
          if vuln_name.match(/[A-z]/)
            vuln_array[vuln_name]["OS"] = line.split(/ - /)[1]
          end
        when /Detected:/
          if vuln_name.match(/[A-z]/)
            info_name = line.split(/:/)[0]
            info_line = line.split(/:/)[1..-1].join(":")
            vuln_array[vuln_name][info_name] = info_line
            headers.push(info_name)
          end
        when /[A-z]:$/
          if vuln_name.match(/[A-z]/)
            if !line.match(/CVSS Environment/)
              if line.match(/^[A-z]/) and line.split(/ /).count < 3 and !line.match(/^[A-Z][A-Z]:$|^[A-z]:$/)
                vuln_array[vuln_name][info_name] = info_data.join("\n")
                info_data = []
                info_name = line.split(/:/)[0]
                headers.push(info_name)
              else
                if mask_data == 1
                  case line
                  when /:[0-9,a-f][0-9,a-f]:[0-9,a-f][0-9,a-f]:/
                    info_data.push(line.gsub(/[0-9,a-f]/,"x"))
                  else
                    info_data.push(line)
                  end
                else
                  info_data.push(line)
                end
              end
            end
          end
        else
          if vuln_name.match(/[A-z]/)
            if mask_data == 1
              case info_name
              when /Asset Group/
                line = "Masked"
              end
              case line
              when /:[0-9,a-f][0-9,a-f]:[0-9,a-f][0-9,a-f]:/
                info_data.push(line.gsub(/[0-9,a-f]/,"x"))
              else
                info_data.push(line)
              end
            else
              info_data.push(line)
            end
          end
        end
      end
    end
  end
  vuln_array[vuln_name]["Hosts"]   = host_list.join("\n")
  vuln_array[vuln_name][info_name] = info_data.join("\n")
  headers = headers.uniq
  if output_file.match(/[A-z]|[0-9]/) and dump_data == 1
    file.close
  end
  return vuln_array,headers
end

def print_results(vuln_array,headers,search_host,search_exploit,search_tag,search_qid,search_cveid,search_bugtraqid,search_cvvs,search_group,search_os,search_status,search_pci,search_string,output_file,output_format,workbook,list_exploits)
  if list_exploits == 1
    vuln_array.each do |vuln_name, vuln_info|
      puts vuln_name
    end
    return
  end
  if output_file.match(/[A-z]|[0-9]/)
    file = File.open(output_file,"w")
  end
  if output_format == "csv"
    output_string = headers.join(",")
    if output_file.match(/[A-z]|[0-9]/)
      file.write(output_string+"\n")
    else
      puts output_string
    end
  end
  if output_format == "xls"
    row = 0
    worksheet  = workbook.add_worksheet('Vulnerability Results')
    format     = workbook.add_format()
    no_headers = headers.length
    format.set_bold(1)
    worksheet.set_column(0,no_headers,20)
    headers.each_with_index do |header, column|   
      if search_tag.match(/[A-z]/) and !header.match(/#{search_tag}/)
        worksheet.set_column(column,column,0)
      end
      worksheet.write(row,column,header)
    end
    format.set_bold(0)
    row = row+1
  end
  vuln_array.each do |vuln_name, vuln_info|
    if !search_exploit.match(/[A-z]/) or vuln_name.match(/#{search_exploit}/)
      if !search_string.match(/[A-z]/) or vuln_array[vuln_name].to_s.match(/#{search_string}/)
        case output_format
        when "csv"
          output_string = vuln_name+","
        when "xls"
          column = 0
          worksheet.write(row,column,vuln_name)
        else
          output_string = "Vulnerability: "+vuln_name+"\n"
          if output_file.match(/[A-z]|[0-9]/)
            file.write(output_string)
          else
            print output_string
          end
        end
        case output_format
        when "csv"
          headers.each do |header|
            if !search_tag.match(/[A-z]/) or header.match(/#{search_tag}/)
              if vuln_array[vuln_name][header]
                value = vuln_array[vuln_name][header]
              else
                value = ""
              end
              value = value.gsub("\n"," ").gsub(/"/,"'")
              output_string = "\""+value+"\","
              if output_file.match(/[A-z]|[0-9]/)
                file.write(output_string)
              else
                print output_string
              end
            end
          end
          if output_file.match(/[A-z]|[0-9]/)
            file.write("\n")
          else
            print "\n"
          end
        when "xls"
          headers.each_with_index do |header, column|
            if !search_tag.match(/[A-z]/) or header.match(/#{search_tag}/)
              if vuln_array[vuln_name][header]
                value = vuln_array[vuln_name][header]
                value = value.gsub(/\n/,"\r")
              else
                value = ""
              end
              worksheet.write(row,column,value)
            end
          end
          row = row+1
        else
          vuln_info.each do |info_name, info_value|
            if !search_host.match(/[A-z]/) or vuln_array[vuln_name]["Hosts"].match(/#{search_host}/)
              if !search_qid.match(/[A-z]/) or vuln_array[vuln_name]["QID"].match(/#{search_qid}/)
                if !search_cveid.match(/[A-z]/) or vuln_array[vuln_name]["CVE ID"].match(/#{search_cveid}/)
                  if !search_cvvs.match(/[A-z]/) or vuln_array[vuln_name]["CVVS"].match(/#{search_cvvs}/)
                    if !search_group.match(/[A-z]/) or vuln_array[vuln_name]["Asset Group"].match(/#{search_group}/)
                      if !search_os.match(/[A-z]/) or vuln_array[vuln_name]["OS"].match(/#{search_os}/)
                        if !search_status.match(/[A-z]/) or vuln_array[vuln_name]["Status"].match(/#{search_status}/)
                          if !search_bugtraqid.match(/[A-z]/) or vuln_array[vuln_name]["Bugtraq ID"].match(/#{search_bugtraqid}/)
                            if !search_pci.match(/[A-z]/) or vuln_array[vuln_name]["PCI Vuln"].match(/#{search_pci}/)
                              if !search_tag.match(/[A-z]/) or info_name.match(/#{search_tag}/)
                                if !info_value.match(/\n/)
                                  puts info_name+": "+info_value
                                else
                                  puts info_name+":"
                                  puts info_value
                                end
                              end
                            end
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end
  if output_file.match(/[A-z]|[0-9]/) 
    if output_format == "xls"
      workbook.close
    else
      file.close
    end
  end
  return
end


# Get command line arguments
# Print help if given none

if !ARGV[0]
  print_usage()
end

# Process options

begin
  option = Getopt::Long.getopts(
    [ "--help",       "-h", Getopt::BOOLEAN ],  # Display usage information
    [ "--version",    "-V", Getopt::BOOLEAN ],  # Display version information
    [ "--verbose",    "-v", Getopt::BOOLEAN ],  # Display debug messages
    [ "--dump",       "-d", Getopt::BOOLEAN ],  # Dump data from PDF to text
    [ "--mask",       "-m", Getopt::BOOLEAN ],  # Mask customer data
    [ "--exploits",   "-X", Getopt::BOOLEAN ],  # List of vulnerabilities
    [ "--exploit",    "-x", Getopt::REQUIRED ], # List of vulnerable servers listed by vulnerability
    [ "--input",      "-i", Getopt::REQUIRED ], # Input file
    [ "--output",     "-o", Getopt::REQUIRED ], # Output file
    [ "--format",     "-f", Getopt::REQUIRED ], # Output format (default is text)
    [ "--host",       "-h", Getopt::REQUIRED ], # Search for host
    [ "--tag",        "-t", Getopt::REQUIRED ], # Search for a tag (e.g. RESULTS)
    [ "--search",     "-s", Getopt::REQUIRED ], # Search for a specific term (e.g. Vulnerability)
    [ "--qid",        "-q", Getopt::REQUIRED ], # Search for a specific QID
    [ "--cveid",      "-c", Getopt::REQUIRED ], # Search for a specific CVE ID
    [ "--bugtraqid",  "-b", Getopt::REQUIRED ], # Search for a specific Bugtraq ID
    [ "--cvvs",       "-C", Getopt::REQUIRED ], # Search for a specific CVVS level
    [ "--group",      "-g", Getopt::REQUIRED ], # Search for a specific Asset Group
    [ "--status",     "-S", Getopt::REQUIRED ], # Search for a specific Status
    [ "--pci",        "-p", Getopt::REQUIRED ], # Search for a specific PCI vulnerability state
    [ "--os",         "-O", Getopt::REQUIRED ]  # Search for a specific OS
  )
rescue
  print_usage()
  exit
end

# Print help information

if option["help"]
  print_usage()
  exit
end

# Print version information

if option["version"]
  print_version()
  exit
end

# Display debug messages

if option["verbose"]
  verbose_mode = 1
else
  verbose_mode = 0
end

# Specifiy a specific host to search for

if option["host"]
  search_host  = option["host"]
  search_chars = search_host.split
  search_chars.each do |char|
    if !char.match(/[0-9]|[A-z]|-/)
      puts "Invalid hostname:"+search_host
      exit
    end
  end
  if verbose_mode == 1
    puts "Searching for host:\t"+search_host
  end
else
  search_host = ""
end

# A generic search

if option["search"]
  search_string = option["search"]
else
  search_string = ""
end

# Search for Asset Group

if option["group"]
  search_group = option["group"]
else
  search_group = ""
end

# Display only a specific tag e.g. QID
# Multiple tags can be displayed via an or e.g "QID|CVEID" 

if option["tag"]
  search_tag = option["tag"]
  search_tag = search_tag.gsub(/CVEID/,"CVE ID")
  if verbose_mode == 1
    puts "Searching for tag:\t"+search_tag
  end
else
  search_tag = ""
end

# Mask customer data like hostnames, MAC addresses, etc


if option["mask"]
  if verbose_mode == 1
    puts "Masking customer data"
  end
  mask_data = 1
else
  mask_data = 0
end

# Specify output file name

if option["output"]
  output_file = option["output"]
  if !option["input"]
    puts "No input file specified"
    exit
  end
else
  output_file = ""
end

# Output a list of vulnerabilities

if option["exploits"]
  list_exploits = 1
else
  list_exploits = 0
end

# Search for a specific vulnerability

if option["exploit"]
  search_exploit = option["exploit"]
  if verbose_mode == 1
    puts "Searching for Vulnerability: "+search_exploit
  end
else
  search_exploit = ""
end

# Search for a specific PCI vulnerability state

if option["pci"]
  search_pci = option["pci"]
  if verbose_mode == 1
    puts "Searching for PCI: "+search_pci
  end
else
  search_pci = ""
end


# Search for a specific QID

if option["qid"]
  search_qid = option["qid"]
  if verbose_mode == 1
    puts "Searching for QID: "+search_qid
  end
else
  search_qid = ""
end

# Search for a specific CVE ID

if option["cveid"]
  search_cveid = option["cveid"]
  if verbose_mode == 1
    puts "Searching for CVE ID: "+search_cveid
  end
else
  search_cveid = ""
end

# Search for a specific Bugtraq ID

if option["bugtraqid"]
  search_bugtraqid = option["bugtraqid"]
  if verbose_mode == 1
    puts "Searching for Bugtraq ID: "+search_bugtraqid
  end
else
  search_bugtraqid = ""
end

# Search for a specific OS

if option["os"]
  search_os = option["os"]
  if verbose_mode == 1
    puts "Searching for OS: "+search_os
  end
else
  search_os = ""
end

# Search for a specific CVVS level

if option["cvvs"]
  search_cvvs = option["cvvs"]
  if verbose_mode == 1
    puts "Searching for CVVS: "+search_cvvs
  end
else
  search_cvvs = ""
end

# Search for a specific CVVS level

if option["status"]
  search_status = option["status"]
  if verbose_mode == 1
    puts "Searching for Status: "+search_status
  end
else
  search_status = ""
end

# Dump raw text from PDF

if option["dump"]
  dump_data = 1
  if verbose_mode == 1
    puts "Setting output type to:\traw"
  end
else
  dump_data = 0
  if option["format"]
    output_format = option["format"].downcase
    output_format = output_format.gsub(/text/,"txt")
    if output_format == "xls"
      if !output_file.match(/[0-9]|[A-z]/)
        puts "Output file not specified for XLS"
        exit
      else
        workbook = WriteExcel.new(output_file)
      end
    end
  else
    output_format = "txt"
  end
  if verbose_mode == 1
    puts "Setting output type to:\t"+output_format
  end
end

if output_file.match(/[A-z]|[0-9]/)
  if !output_file.match(/\.#{output_format}/)
    output_file = output_file+"."+output_format
  end
  if verbose_mode == 1
    puts "Setting output file to:\t"+output_file
  end
end

if option["input"]
  input_file = option["input"]
  if !File.exist?(input_file)
    puts "File: "+input_file+" does not exist"
    exit
  end
  if verbose_mode == 1
    puts "Setting input file to:\t"+input_file
  end
  vuln_array = Hash.new{|hash, key| hash[key] = Hash.new}
  headers    = []
  (vuln_array,headers) = process_pdf(input_file,output_file,vuln_array,headers,dump_data,mask_data)
  if dump_data == 0
    print_results(vuln_array,headers,search_host,search_exploit,search_tag,search_qid,search_cveid,search_bugtraqid,search_cvvs,search_group,search_os,search_status,search_pci,search_string,output_file,output_format,workbook,list_exploits)
  end
end

