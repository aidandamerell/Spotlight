#!/usr/bin/env ruby
#written by Aidan Damerell - 2018
$VERBOSE = nil #This just prevent certificate errors being thrown if we connect to a LDAPS server using the IP address

require 'net/ldap'
require 'tty-command'
require 'trollop'
require 'colorize'
require 'yaml'
require 'resolv'
require 'axlsx'
require_relative './objects.rb'
require 'pp'

banner = <<-EOF
  __               
 (     _// '_ /_/_
__)/)()/(_/(//)/  
  /       _/
V0.4 : 55W
EOF


opts = Trollop::options do
	opt :host, "Domain Controller IP / Hostname".bold, :type => :string, :short => "-h"
	opt :username, "Domain Username".bold, :type => :string, :short => "-u"
	opt :password, "Domain Password".bold, :type => :string, :short => "-p"
	opt :domain, "Domain Name".bold, :type => :string, :short => "-d"
	opt :all, "Do Everything", :type => :boolean, :short => "-A"
	opt :queryuser, "Query a single user", :type => :string
	opt :querygroup, "Query a single group", :type => :string, :short => "-q"
	opt :admingroups, "Enumerate common administrative groups", :type => :boolean
	opt :enumtrusts, "Enumerate Active Directory trusts", :type => :boolean, :short => "-t"
	opt :usersandgroups, "Enumerate all users and groups in the domain", :type => :boolean, :short => "-b"
	opt :hashdump, "Dump the groups user hashes, requires privs", :type => :boolean, :short => "-H"
	opt :computers, "Find all the domain joined machines (options: all, workstations, servers, domaincontrollers)", :type => :string, :short => "-c"
	opt :output, "Output the datastores (Domain,Users,Groups,Computer) to excel", :type => :boolean, :short => "-o"
	opt :restore, "Restore from YAML log file", :type => :string, :short => "-r"
	opt :external, "List of usernames from external OSINT", :type => :string
	opt :kerberoast, "Kerberoast the domain", :type => :boolean, :short => "-k"
	opt :noresolve, "Don't Resolve DNS Names", :type => :boolean, :short => "-R"
	opt :cracked, "A list of cracked credentials from which to add to the users output", :type => :string
	opt :redacted, "Redact the output AND YAML", :type => :boolean
end

if opts[:all]
	opts[:usersandgroups] = true
	opts[:hashdump] = true
	opts[:computers] = "all"
	opts[:kerberoast] = true
end

puts banner.light_blue

#Main Functions for all objects
##Hashdump
def hashdump(options)
	catch :noprivs do 
		opts = options[:opts]
		case options[:type]
			when 0
				puts "Dumping hash for user #{options[:user].name}".green
				cmd = TTY::Command.new(output: '', printer: :quiet)
				connection = cmd.run("python /usr/local/bin/secretsdump.py \'#{opts[:domain]}/#{opts[:username]}\:#{opts[:password]}\'\@#{opts[:host]} -just-dc-ntlm -just-dc-user \"#{opts[:domain]}/#{options[:user].name}\"")
				if connection.out =~ /\:\:\:$/
					LDAPData::User.add_hash(connection.out.split("\n")[4])
				end
			when 1
				puts "Dumping hashes for all found users".green
				cmd = TTY::Command.new(output: '', printer: :quiet)
				connection =  cmd.run("python /usr/local/bin/secretsdump.py \'#{opts[:domain]}/#{opts[:username]}\:#{opts[:password]}\'\@#{opts[:host]} -just-dc-ntlm")
				connection.each do |line|
					if line.include? ":::"
						LDAPData::User.add_hash(line)
					elsif line.include? "ERROR_DS_DRA_ACCESS_DENIED"
						puts "Not enough privilege, aborting hashdump".red
						throw :noprivs
					end
				end
		end
	end
end

##Shutdown
def shutdown
	Puts "Exiting...".red
	exit
end

##Output
def output(object)
	#Takes an object and outputs it in a pretty way
	object.instance_variables.each do |attribute|
		print attribute.to_s.gsub("@","").capitalize
		print ": "
		case value = object.instance_variable_get(attribute)
		when Array
			puts value.join(", ")
		when String
			puts value
		when Fixnum
			puts value
		when nil
			puts "NIL"
		when true
			puts "TRUE"
		end
	end
	puts ""
end

#Create and edit a sheet
def swrite(wb_object,worksheet,array,objects,attributes)
	#workbook is the object, worksheet will be the name of the new sheet, array will be the header row, objects will be the array of objects
	#attributes in an array of attributes - this is to control layout
	wb_object.add_worksheet(:name => worksheet) do |sheet|
		sheet.add_row array
		objects.each do |object|
			if attributes
				sheet.add_row attributes.map { |attribute|
					if object.instance_variable_get(attribute).is_a? Array
						object.instance_variable_get(attribute).join(", ")
					else
						object.instance_variable_get(attribute)
					end
					}
			else
				sheet.add_row object.instance_variables.map { |attribute|
					if object.instance_variable_get(attribute).is_a? Array
						object.instance_variable_get(attribute).join(", ")
					else
						object.instance_variable_get(attribute)
					end
				}
			end
		end
	end
end

def password_policy_output(wb_object, data)
	wb_object.add_worksheet(:name => "Password Policy") do |sheet|
		sheet.add_row ["Setting", "Value", "NCC Recommendation"]
		sheet.add_row ["Domain Name", data.name]
		sheet.add_row ["Max Password Age", data.maxpwdage,"< 42 Days"]
		sheet.add_row ["Min Password Age", data.minpwdage,"1 Day"]
		sheet.add_row ["Lockout Window", data.lockoutobservationwindow,"15 Minutes"]
		sheet.add_row ["Lockout Duration", data.lockoutduration,"30 Minutes"]
		sheet.add_row ["Lockout Threshold", data.lockoutthreshold,"3 - 6 Attempts"]
		sheet.add_row ["Min Password Length", data.minpwdlength, "10 Characters"]
		sheet.add_row ["Password Properties", data.pwdproperties,"DOMAIN PASSWORD COMPLEX"]
		sheet.add_row ["Password History", data.pwdhistorylength,"> 12 Passwords"]
	end

end

case opts[:restore]
	when nil
		begin
			ldap_con = Net::LDAP.new(
				{:host => opts[:host],
					:encryption => 
						{ method: :simple_tls, :tls_options => { verify_mode: OpenSSL::SSL::VERIFY_NONE},
					},
					:port => 636,
					:auth => {:method => :simple, :username => "#{opts[:domain]}\\#{opts[:username]}", :password => "#{opts[:password]}" }
				}
				)
			ldap_con.bind
		rescue Net::LDAP::Error => e
			puts "Unable to connect over LDAPS, Reason: #{e}".yellow
			puts "Would you like to use insecure LDAP? Y/N".yellow
			print "Choice:".light_blue
			if gets.chomp.downcase == "y"
				#Insecure LDAP
				ldap_con = Net::LDAP.new(
				{:host => opts[:host], :port => 389,
				:auth => { :method => :simple, :username => "#{opts[:domain]}\\#{opts[:username]}", :password => "#{opts[:password]}" }})
			else
				puts "Cancelling".green
				shutdown
			end
		end

		begin
			#Check that the connection bound to LDAP
			if ldap_con.bind
				puts "[+] LDAP connection successful with credentials: #{opts[:domain]}\\#{opts[:username]}:#{opts[:password]}\n".green
			end
		rescue Net::LDAP::Error => e
			puts "[-] Hmm, unable to connect to LDAP/LDAP #{e}".red
			# shut_down
		end

		begin
			#Get the naming context for the domain
			puts "Querying RootDSE for FQDN...\n".green
			naming_context = []
			ldap_con.search_root_dse.namingcontexts.each_with_index do |context, index|
				naming_context[index] = a_context = context.to_s
				if a_context.split(",")[0] =~ /#{opts[:domain]}/i
					puts "[#{index}] #{a_context}".green
					@treebase = a_context
				else
					puts "[#{index}] #{a_context}".red
				end
			end
			#Check the treebase was set and if not query the user for it
			if @treebase
				puts "\nTreebase found: #{@treebase}".green
				#create a FQDN from the treebase to use in kerberoasting and hashdumping
				@fqdn = @treebase.gsub(",DC=",".").sub("DC=","")
				puts "FQDN Enumerated: #{@fqdn}".green
			else
				print "Unable to find, please choose using above numbers:".yellow
				@treebase = naming_context[gets.chomp.to_i]
			end

		rescue => e
			puts "Error: #{e}".red
			puts "Please check your credentials, exiting".red
			shut_down
		end

		puts "Enumerating domain: #{@fqdn}\n".green
		ldap_con.search( :base => @treebase, :filter => LDAPData.current_domain_info) do |domain|
			current = LDAPData.entry_to_hash(domain)
			current[:current] = true
			LDAPData::Domain.new(current)
			output(LDAPData::Domain.current)
		end

	when opts[:restore]
		#Logic to repopulate each data object from YAML data
		puts "Reading YAML: #{opts[:restore]}".light_blue
		YAML.load_file(opts[:restore]).each do |object|
			if object.is_a? LDAPData::User
				LDAPData::User.all_users << object
			elsif object.is_a? LDAPData::Group
				LDAPData::Group.all_groups << object
			elsif object.is_a? LDAPData::Computer
				LDAPData::Computer.all_computers << object
			elsif object.is_a? LDAPData::Domain
				LDAPData::Domain.all_domains << object
			end
		end
		puts "Users: #{LDAPData::User.all_users.count}"
		puts "Groups: #{LDAPData::Group.all_groups.count}"
		puts "Computers: #{LDAPData::Computer.all_computers.count}"
		puts "Domains: #{LDAPData::Domain.all_domains.count}"
		@fqdn = LDAPData::Domain.current.fqdn
end

#Get indivual user
if opts[:queryuser]
	puts "Querying user: #{opts[:queryuser]}".green
	ldap_con.search( :base => @treebase, :filter => LDAPData.find_one_user(opts[:queryuser])) do |user|
		@user = LDAPData::User.new(LDAPData.entry_to_hash(user))
		@user.memberof = [] #This is to avoid duplications of data as the User object will use the standard member of, which we dont really want
		ldap_con.search( :base => @treebase, :filter => LDAPData.recursive_user_memberof(@user.dn)) do |group|
			@user.memberof << LDAPData::Group.new(LDAPData.entry_to_hash(group)).name
		end
	end
	if opts[:hashdump] then hashdump(type: 0, user: @user,opts: opts) end
	if @user then puts "Found user: #{@user.name}".green end
	output(@user)
end

#Get individual group
#I'm going to leave out the recursion option here, you're only enumerating one group so it really wont take too long
if opts[:querygroup]
	puts "Querying Group: #{opts[:querygroup]}".green
	ldap_con.search( :base => @treebase, :filter => LDAPData.find_one_group(opts[:querygroup])) do |group|
		@group = LDAPData::Group.new(LDAPData.entry_to_hash(group))
		@group.members = []
		ldap_con.search( :base => @treebase, :filter => LDAPData.recursive_group_memberof(@group.dn)) do |nested|
			@user = LDAPData::User.new(LDAPData.entry_to_hash(nested))
			@group.members << @user.name
			if opts[:hashdump] then hashdump(type: 0, user: @user,opts: opts) end
		end
		@group.count = @group.members.count #This value is normally set on initialize so I need to update it
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
	ldap_con.search( :base => @treebase, :filter => LDAPData.find_all_users) do |user|
		LDAPData::User.new(LDAPData.entry_to_hash(user))
	end
	puts "Finding all groups in #{@fqdn} domain\n".green
	ldap_con.search( :base => @treebase, :filter => LDAPData.find_all_groups) do |group|
		@created_group = LDAPData::Group.new(LDAPData.entry_to_hash(group))
		if @created_group.administrative
			puts "Running nested enumeration on #{@created_group.name}".green
			@created_group.members = []
			ldap_con.search( :base => @treebase, :filter => LDAPData.recursive_group_memberof(@created_group.dn)) do |recurse|
				@created_group.members << LDAPData.entry_to_hash(recurse)[:name]
			end
		end
		@created_group.count = @created_group.members.count
	end
	puts "Found Users: #{LDAPData::User.all_users.count}"
	puts "Found Groups: #{LDAPData::Group.all_groups.count}"
	if opts[:hashdump] then hashdump(type: 1, array: LDAPData::User.all_users,opts: opts) end
end

# if opts[:admingroups] and !opts[:usersandgroups]
# 	puts "Finding admin groups in #{@fqdn} domain\n".green
# 	LDAPData::Group.administrative_groups.each do |admin_group|
# 		ldap_con.search( :base => @treebase, :filter => LDAPData.find_one_group(admin_group.name)) do |group|
# 			@created_group = LDAPData::Group.new(LDAPData.entry_to_hash(group))
# 			puts "Running nested enumeration on #{@created_group.name}".green
# 			@created_group.members = []
# 				ldap_con.search( :base => @treebase, :filter => LDAPData.recursive_group_memberof(@created_group.dn)) do |recurse|
# 					@created_group.members << user = LDAPData.entry_to_hash(recurse)[:name]
# 					if opts[:hashdump] then hashdump(type: 0, user: user,opts: opts) end
# 				end
# 			end
# 			@created_group.count = @created_group.members.count
# 		end
# 	end
# end


# #Get domain trusts
if opts[:enumtrusts]
	puts "Finding all domains associated with #{@fqdn}\n".green
	ldap_con.search( :base => @treebase, :filter => LDAPData.find_domain_trusts) do |domain|
		domain = LDAPData::Domain.new(LDAPData.entry_to_hash(domain))
		output(domain)
	end
end

#Domain computers
if opts[:computers]
	resolver =  Resolv::DNS.new(:nameserver => ["#{opts[:host]}"]) #Create this because otherwise we have to create one for each object and thats just bad code
	puts "Finding computers\n".green
	ldap_con.search( :base => @treebase, :filter => LDAPData.find_computer(opts[:computers])) do |computer|
		host = LDAPData::Computer.new(LDAPData.entry_to_hash(computer))
		unless opts[:noresolve]
			host.ip = LDAPData::Computer.resolver(resolver,host.dns)
		end
		puts "#{host.name} : #{host.ip} : #{host.os} : #{host.os_sp}"
	end
end

#Kerberoast
#Need to add in functionality to check for administrators
if opts[:kerberoast]
	begin
		output = ''
		cmd = TTY::Command.new(output: output, printer: :quiet)
		#this path is correct in both OSX and Kali
		connection = cmd.run("python /usr/local/bin/GetUserSPNs.py #{@fqdn}/#{opts[:username]}\:\'#{opts[:password]}\' -dc-ip #{opts[:host]} -outputfile #{@fqdn}_kerberoast.txt")
		if cmd.err.empty?
			puts "Kerberoast completed, written file.".green
		end
	rescue NoMethodError
		puts "Error Dumping Kerberos hashes".red
	end
end

if opts[:cracked]
	LDAPData::User.cracked(File.open(opts[:cracked]))
end
if opts[:external]
	LDAPData::User.external(File.open(opts[:external]))
end

if opts[:redacted]
	print "This will remove hashes and passwords from both the excel document AND YAML logs. Continue? Y/N:".yellow
	if gets.chomp.downcase == "y"
		LDAPData::User.redact
	end
end

#Restore functionality, write all object arrays to YAML
unless opts[:restore]
	begin
		puts "\nWriting YAML files for logs".green
		array = [ LDAPData::Group.all_groups, LDAPData::User.all_users, LDAPData::Domain.all_domains, LDAPData::Computer.all_computers]
		File.write("./logs/#{Time.now.strftime('%Y-%m-%d_%H-%M')}_connection_data.yaml", array.flatten.to_yaml)
	rescue => e
		puts "Error writing YAML".red
	end
end

#Excel output
if opts[:output]
	xlsx_object = Axlsx::Package.new
	wb_object = xlsx_object.workbook
	puts "writing XLSX output".green
	swrite(wb_object,"Users",["Name","When Created","Expires","Enabled","Time Since bad password", "Member Of","Hash","Hash Type","Password","Found Externally"], LDAPData::User.all_users, [:@name, :@whencreated, :@accountexpires,:@enabled, 
		:@badpasswordtime, :@memberof, :@hash,:@hash_type, :@password, :@external])
	swrite(wb_object,"Groups",["Name","Members","Count","DN"], LDAPData::Group.all_groups,[:@name,:@members,:@count,:@dn])
	swrite(wb_object,"Administrative Groups",["Name","Members","Count","DN"], LDAPData::Group.administrative_groups,[:@name,:@members,:@count,:@dn])
	swrite(wb_object,"Domains",["Name","Trust Direction","Trust Type","Trust Attributes","Flat name","DN"], LDAPData::Domain.all_domains,[:@name,:@trustdirection,:@trusttype,:@trustattributes, :@flatname, :@dn])
	swrite(wb_object,"Computers",["Name","OS","OS SP","FQDN","IP"], LDAPData::Computer.all_computers,[:@name,:@os,:@os_sp,:@dns,:@ip])
	password_policy_output(wb_object,LDAPData::Domain.current)
	if xlsx_object.serialize("#{@fqdn}_output.xlsx")
		puts "Writing XLSX successful".green
	else
		puts "Error writing XLSX".red
	end
	if opts[:hashdump] || opts[:restore]
		File.open("#{@fqdn}_hashdump.txt", "w+") do |file|
			LDAPData::User.all_users.each do |user|
				file.puts user.hash
			end
		end
	end

end