#!/usr/bin/env ruby
require 'pp'

def osx_kextstats
  kexts, refs_to_names = {}, {}
  kextstats = `kextstat`.split("\n")
  kextstats.slice!(0) # skip header
  kextstats.each do |line|
    values = line.split
    num, refs, addr, size, wired, name, ver = values.slice(0..6)
    refs = values.slice(7..values.size)
    refs = refs.collect do |ref|
      ref = ref.gsub(/[<>]/, "").to_i
      raise "Bad reference number" if ref.zero?
      refs_to_names[ref]
    end
    ver = ver.slice(1..ver.size-2)
    modvals =  {
      :index => num.to_i,
      :refs => refs,
      :addr => addr,
      :size => sprintf("%d", size).to_i,
      :wired => wired,
      :name => name,
      :ver => ver,
      :refs => refs,
    }
    kexts[name] = modvals
    # Add a lookup by index number too.
    refs_to_names[modvals[:index]] = name
  end
  kexts
end

@kexts = osx_kextstats

def run(cmd)
  puts "==> Running: #{cmd}"
  system(cmd) or raise "Command failed!"
end

@tmpdir = "/tmp"
@stackshot = "#{@tmp}/stackshot.log"

run "/usr/libexec/stackshot -i -f #{@stackshot}"

@domain = "org.openzfsonosx"
# Only work on modules actually loaded.
@mods = %w(spl zfs).select {|mod| @kexts["#{@domain}.#{mod}"]}
@modules = @mods.collect {|mod| "/System/Library/Extensions/#{mod}.kext"}

puts "Symbols for kextutil:"
@mods.each do |mod|
  m = @kexts["#{@domain}.#{mod}"]
  puts "#{mod}: #{m[:addr]}" if m
end

dbgkit = "/Volumes/KernelDebugKit"
kern = "#{dbgkit}/mach_kernel"
run "kextutil -s #{@tmpdir} -n -k #{kern} -e -r #{dbgkit} #{@modules.join(' ')}"

@mods.each do |mod|
  modf = "#{@tmpdir}/#{@domain}.#{mod}"
  puts "Stacks for #{mod}.kext in #{modf}.log ..."
  run "symstacks.rb -f #{@stackshot} -s -k #{modf}.sym -w #{modf}.log"
end
