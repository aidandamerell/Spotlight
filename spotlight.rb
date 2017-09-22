#!/usr/bin/env ruby -W0
#-W0 as net-ldap tries to warn of certificate mismatch
#written by Aidan Damerell - 2017

require 'net/ldap'
require 'tty-command'
require 'trollop'
require 'colorize'
require 'yaml'
require 'csv'
require './objects.rb'


Signal.trap("INT") { 
  shut_down 
  exit
}

def shut_down
  puts "\nShutting down...".light_blue
  exit
end



banner = <<-EOF
  __               
 (     _// '_ /_/_
__)/)()/(_/(//)/  
  /       _/
EOF

puts banner.light_blue

if ARGV[0].nil?
	puts "Need help? tryp ./spotlight.rb --help".light_blue
	shut_down
end

opts = Trollop::options do
	opt :all, "Do everything", :type => :boolean
	opt :host, "LDAP Host", :type => :string
	opt :username, "Domain Username", :type => :string
	opt :password, "Domain Password", :type => :string
	opt :domain, "Domain Name", :type => :string
	opt :tld, "Top Level Domain, or any other DN value which exist - E.G. child.parent.local", :type => :string, :default => "local"
	opt :groupname, "Name of group to enumerate", :type => :string
	opt :ldaptype, "Use unecrypted LDAP", :type => :boolean
	opt :dumphashes, "Dump the groups user hashes, account requires domain administrative privilege", :type => :boolean
	opt :enumgroups, "Enumerate groups and member count", :type => :boolean
	opt :enumtrusts, "Enumerate Active Directory trusts", :type => :boolean
	opt :enumallusers, "Enumerate all users on the domain", :type => :boolean
	opt :queryuser, "Query the membership of a single user", :type => :string
	opt :domaincomputers, "Find all the domain joined machines (options: all, workstations, servers, domaincontrollers)", :type => :string
	opt :cracked, "A list of cracked credentials from which to add to the users output", :type => :string
	opt :csv, "CSV output", :type => :boolean
	opt :restore, "Restore from YAML log file", :type => :string
end
if opts[:all]
	puts "Running all functions...".green
	opts[:enumtrusts] = true
	opts[:dumphashes] = true
	opts[:enumallusers] = true
	opts [:enumgroups] = true
	opts[:csv] = true
	opts[:domaincomputers] = "all"
end


#create LDAP connections
unless opts[:restore]
	if opts[:ldaptype]
		ldap_con = Net::LDAP.new(
			{:host => opts[:host],
			 :port => 389,
			  :auth =>
		    	{ :method => :simple,
		    	 :username => "#{opts[:domain]}\\#{opts[:username]}",
		    	  :password => opts[:password] }
		    	  }
		    	  )
	else
		ldap_con = Net::LDAP.new(
		{:host => opts[:host],
	     	:encryption => {
	        method: :simple_tls,
	        :tls_options => { verify_mode: OpenSSL::SSL::VERIFY_NONE}, #verify none is to prevent crashing when an IP doesnt match the SSL cert CN
	      },
		 :port => 636,
		  :auth =>
	    	{ :method => :simple,
	    	 :username => "#{opts[:domain]}\\#{opts[:username]}",
	    	  :password => opts[:password] }
	    	  }
	    	  )
	end
end

#check LDAP
unless opts[:restore]
	begin
		if ldap_con.bind
			puts "LDAP connection successful with credentials #{opts[:username]}:#{opts[:password]}\n".green
			tld = opts[:tld].split("\.").join(",dc=")
			treebase = "dc=#{opts[:domain]},dc=#{tld}"
		else
			puts "Unable to authenticate to LDAP, Error: #{ldap_con.get_operation_result.message}, you need a username, password and domain".red
			exit
		end
	rescue Net::LDAP::Error => e
		puts "Hmm, unable to connect to LDAP/LDAP #{e}".red
		exit
	end
else
	YAML.load_file(opts[:restore]).each do |object|
		if object.is_a? User
			# puts "parsed user"
			User.all_users << object
		elsif object.is_a? Group
			# puts "parsed group"
			Group.all_groups << object
		elsif object.is_a? Computer
			# puts "parsed computer"
			Computer.all_computers << object
		end
	end
end

if opts[:enumtrusts]
	puts "Enumerating Domain Trusts...".green

	ldap_con.search( :base => treebase, :filter => Domain.domain_info) do |entry|
		puts "\nQueried Domain Name: #{entry.dc.entries.reduce}"
		puts "Queried Domain TLD: #{entry.dn.split("DC=")[-1]}"
		puts "Queried DC: #{entry.masteredby.entries.to_s.split("CN=")[2]}\n\n"
		Domain.current(entry)
	end
	ldap_con.search( :base => treebase, :filter => Domain.find_trusts) do |entry|
		Domain.new(entry)
	end
	Domain.all_domains.each do |trust|
		puts "---------------------------"
		puts "Domain Name: #{trust.name}"
		puts "Trust Direction: #{trust.trust_direction}"
		puts "Trust Type: #{trust.trust_type}"
		puts "Trust Attributes: #{trust.trust_attributes}\n"
		puts "Relation: #{trust.relation}"
	end
end

if opts[:queryuser]
	puts "Quering user #{opts[:queryuser]}...\n".green
	ldap_con.search( :base => treebase, :filter => User.find_user(opts[:queryuser])) do |entry|
		member_of = []
		ldap_con.search( :base => treebase, :filter => User.recursive_user_memberof(entry.dn)) do |memberofs| #use the recursive member of function
			member_of << memberofs.name
		end
		User.new(entry, member_of)
			User.all_users.each do |u|
				puts "Username: #{u.name}"
				puts "Admin: #{u.admin}"
				puts "Enabled: #{u.enabled}"
				puts "Logon Count: #{u.logon_count}"
				puts "Member of: #{u.member_of.join(", ")}"
				puts "Created: #{u.when_created}"
				puts "Modified: #{u.when_changed}"
				puts "Last incorrect password attempt: #{u.bad_password_time}"
				puts "Expires: #{u.account_expires}"
				puts "Last Logon: #{u.last_logon}"
				puts "Descriptions: #{u.description}"
			end
	end
	if User.all_users.empty?
		puts "Couldn't find user: #{opts[:queryuser]}".red
	end
end

#find all groups
if opts[:enumgroups]
	puts "Parsing groups...\n".green
	ldap_con.search( :base => treebase, :filter => Group.find_all_groups()) do |entry|
		i = Group.new(entry, nil)
		member_of = []
		ldap_con.search( :base => treebase, :filter => Group.recursive_memberof(i)) do |memberofs| #use the recursive member of function
			i.members << memberofs.name
			User.new(memberofs, nil)
		end
		puts "Group Name: #{i.name} - Members: #{i.members.count}"
	end
end

if opts[:enumallusers]
	puts "Enumerating all users...\n".green
		ldap_con.search( :base => treebase, :filter => User.find_all_users) do |entry|
			member_of = []
			ldap_con.search( :base => treebase, :filter => User.recursive_user_memberof(entry.dn)) do |memberofs| #use the recursive member of function
				member_of << memberofs.name
			end
			u = User.new(entry, member_of)
			puts "Name: #{u.name} - Admin: #{u.admin} - Description: #{u.description}"
		end
		puts "\nFound #{User.all_users.count} users".green
end

if opts[:domaincomputers]
	if opts[:domaincomputers] == "all"
		filter = Computer.find_all_computers
	elsif opts[:domaincomputers] == "workstations"
		filter = Computer.find_all_workstations
	elsif opts[:domaincomputers] == "servers"
		filter = Computer.find_all_servers
	elsif opts[:domaincomputers] == "domaincontrollers"
		filter = Computer.find_all_domaincontrollers
	end
	ldap_con.search( :base => treebase, :filter => filter) do |entry|
		Computer.new(entry)
	end
	puts "Enumerating computers, type: #{opts[:domaincomputers]}".green
	puts "Name:OS:DNS:IP"
	Computer.all_computers.each do |c|
		puts "#{c.cn}:#{c.os}:#{c.dns}:#{c.ip}"
	end
	puts "------------------\n"
end


if opts[:groupname]
	#search for the group and create a Group object with the attributes
	ldap_con.search( :base => treebase, :filter => Net::LDAP::Filter.construct("(name=#{opts[:groupname]}))")) do |entry|
		member_obj = entry.member rescue []
		Group.new(entry,member_obj)
	end
	Group.find_group(opts[:groupname])

	unless Group.all_groups.empty?
		puts "Found Group: #{opts[:groupname]}, Objects: #{Group.search_group.members.count}".green
	else
		puts "Unable to find group \"#{opts[:groupname]}\", is the TLD correct?".red
		exit
	end

	# use the memberof LDAP query to pull back all users and nested users in the group
	ldap_con.search( :base => treebase, :filter => Group.recursive_memberof(Group.search_group)) do |entry|
		member_of = entry.memberof.entries.reduce rescue nil
		u = User.new(entry, member_of)
		puts "Name: #{u.name} - admin: #{u.admin}"
	end

	User.all_users.each do |user|
		Group.search_group.members.each do |group|
			begin
				if user.member_of.include? group
					linked = group.split(",")[0]
					user.link = linked.gsub(/CN=/, '')
				end
			rescue
			end
		end
	end
end

catch :nopriv do #err, I think this works...
	if opts[:dumphashes]
		puts "------------------\n"
		puts "Dumping Hashes...\nHashes:".green
		#dump the hashes
		# Child domain enumeration doesnt work
		User.all_users.uniq! {|u| u.name}
		unless User.all_users.empty?
			User.all_users.each do |user|
				output = ''
				cmd = TTY::Command.new(output: output)
				#this path is correct in both OSX and Kali
				connection = cmd.run("python /usr/local/bin/secretsdump.py #{opts[:domain]}/#{opts[:username]}\:\"#{opts[:password]}\"\@#{opts[:host]} -just-dc-user \"#{opts[:domain]}/#{user.name}\"")
				unless connection.out =~ /ERROR_DS_DRA_ACCESS_DENIED|ERROR_DS_DRA_BAD_DN/ #secretsdump doesnt output to STDERR, annoyingly
					user.hash = connection.out.split("\n")[4]
					User.hash_type(user)
					puts user.hash
				else
					puts "Not enough privilege, aborting hashdump".red
					throw :nopriv
				end
			end
			puts "\nWriting to JTR readable format".green
			File.open("spotlight_to_john.txt", "w+") do |line|
				User.all_users.each do |user|
					line << "#{user.hash}\n"
				end
			end
		else
			puts "No Users, aborting hashdump".red
			throw :nopriv
		end
	end
end

if opts[:cracked]
	File.readlines(opts[:cracked]).each do |i|
		User.cracked(i)
	end
end
#Some CSV output
if opts[:csv]
	puts "Writing CSV Files".green
	if opts[:groupname] || opts[:restore]
		unless User.all_users.empty?
			CSV.open("users_output.csv", "w+") do |csv|
				csv << ["Username", "Group", "Linked Group", "Logon Count", "Hash", "Hash Type", "Password"]
				User.all_users.each do |user|
					csv << [user.name, opts[:groupname],user.link, user.logon_count, user.hash, user.hash_type, user.password]
				end
			end
		end
	end
	if opts[:enumgroups] 
		CSV.open("allgroups_output.csv", "w+") do |csv|
			csv << ["Group", "Admin?", "Members"]
			Group.all_groups.each do |grp|
				csv << [grp.name, grp.admin, grp.members.join(", ")]
			end
		end
	end

	if opts[:enumallusers]
		CSV.open("allusers_output.csv", "w+") do |csv|
			csv << ["Username", "Admin?", "Created", "Changed", "Password Last Changed", "Last bad password attempt","Expires","Enabled?","Logon Count","Hash", "Hash Type", "Password", "Member Of"]
			User.all_users.each do |usr|
				usr.member_of = [] if usr.member_of.nil?
				csv << [usr.name, usr.admin, usr.when_created, usr.when_changed, usr.pwdlastset ,usr.bad_password_time, usr.account_expires, usr.enabled, usr.logon_count, usr.hash, usr.hash_type, usr.password, usr.member_of.join(", ")]
			# ^ Not exactly following the Ruby format guidelines
			end
		end
	end

	if opts[:domaincomputers] || opts[:restore] && opts[:domaincomputers]
		CSV.open("computer_output.csv", "w+") do |csv|
			csv << ["Name","OS","DNS","IP"]
			Computer.all_computers.each do |computer|
				csv << [computer.cn, computer.os, computer.dns, computer.ip]
			end
		end
	end
end


unless opts[:restore]
	begin
		puts "\nWriting YAML files for logs".green
		array = [ Group.search_group, Group.all_groups, Computer.all_computers, User.all_users, Domain.all_domains]
		File.write("./logs/connection_data.yaml", array.flatten.to_yaml)
	rescue => e
		puts "Something went wrong \"#{e}\""
	end
end