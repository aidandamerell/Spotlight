#!/usr/bin/env ruby
#-W0 as net-ldap tries to warn of certificate mismatch
#written by Aidan Damerell - 2017

require 'net/ldap'
require 'tty-command'
require 'trollop'
require 'colorize'
require 'yaml'
require 'csv'
require 'pp'
require 'terminal-table'
require_relative './objects.rb' #Allows the require to be determined from where the script runs rather than where the user runs the script


Signal.trap("INT") { 
  shut_down 
  exit
}

def shut_down
  puts "\nShutting down...".light_blue
  write_logs
  exit
end

def write_logs
		begin
		puts "\nWriting YAML files for logs".green
		array = [ Group.search_group, Group.all_groups, Computer.all_computers, User.all_users, Domain.all_domains]
		File.write("#{Time.now.strftime('%Y-%m-%d_%H-%M')}_connection_data.yaml", array.flatten.to_yaml)
	rescue => e
		puts "Something went wrong \"#{e}\"".red
	end
end

if ARGV[0].nil?
	puts "Need help? Try ruby ./spotlight.rb --help".light_blue
	shut_down
end


banner = <<-EOF
  __               
 (     _// '_ /_/_
__)/)()/(_/(//)/  
  /       _/
EOF

puts banner.light_blue


opts = Trollop::options do
	opt :all, "Do everything", :type => :boolean
	opt :host, "LDAP Host", :type => :string
	opt :username, "Domain Username", :type => :string
	opt :password, "Domain Password", :type => :string
	opt :domain, "Domain Name", :type => :string
	opt :tld, "Top Level Domain, or any other DN value which exist - E.G. child.parent.local", :type => :string, :default => "local"
	opt :groupname, "Name of group to enumerate", :type => :string
	opt :ldaptype, "Use unecrypted LDAP", :type => :boolean
	opt :enumgroups, "Enumerate groups and member count", :type => :boolean
	opt :enumtrusts, "Enumerate Active Directory trusts", :type => :boolean
	opt :nonestedmembers, "Do not perform Nested Member of", :type => :boolean #not implemented
	opt :enumallusers, "Enumerate all users on the domain", :type => :boolean
	opt :findadmins, "Find users who are Admins", :type => :boolean
	opt :queryuser, "Query the membership of a single user", :type => :string
	opt :dumphashes, "Dump the groups user hashes, account requires domain administrative privilege", :type => :boolean
	opt :domaincomputers, "Find all the domain joined machines (options: all, workstations, servers, domaincontrollers)", :type => :string
	opt :cracked, "A list of cracked credentials from which to add to the users output", :type => :string
	opt :csv, "CSV output", :type => :boolean
	opt :restore, "Restore from YAML log file", :type => :string
	opt :redacted, "Output to CSV without sensitive information", :type => :boolean
	opt :external, "List of usernames from external OSINT", :type => :string
end

if opts[:findadmins]
	opts[:groupname] = "Administrators"
end

if opts[:all]
	puts "Running all functions...".green
	opts[:enumtrusts] = true
	opts[:dumphashes] = true
	opts[:enumallusers] = true
	opts[:enumgroups] = true
	opts[:csv] = true
	opts[:domaincomputers] = "all"
	opts[:nonestedmembers] = true
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

#check LDAP & restore functionality
unless opts[:restore]
	begin
		if ldap_con.bind
			puts "[+] LDAP connection successful with credentials: #{opts[:domain]}\\#{opts[:username]}:#{opts[:password]}\n".green
			ldap_con.search_root_dse.namingcontexts.each do |context|
				if context.include? "#{opts[:domain]}"
					if context.split(",")[0] =~ /#{opts[:domain]}/
						puts @treebase = context.to_s
					end
				end
			end
			puts "@treebase:#{@treebase}"
		else
			puts "[-] Unable to authenticate to LDAP, Error: #{ldap_con.get_operation_result.message}, you need a username, password and domain".red
			puts "Tried with #{opts[:domain]}\\#{opts[:username]}:#{opts[:password]}\n"
			exit
		end
	rescue Net::LDAP::Error => e
		puts "[-] Hmm, unable to connect to LDAP/LDAP #{e}".red
		exit
	end
else
	YAML.load_file(opts[:restore]).each do |object|
		if object.is_a? User
			User.all_users << object
		elsif object.is_a? Group
			Group.all_groups << object
		elsif object.is_a? Computer
			Computer.all_computers << object
		end
	end
end
#Takes cracked passwords and feeds them back into Users objects
if opts[:cracked]
	File.readlines(opts[:cracked]).each do |hash|
		User.cracked(hash)
	end
end
#Takes external users and feeds them back into Users objects
if opts[:external]
	File.readlines(opts[:external]).each do |username|
		User.external(username)
	end
end



unless opts[:restore]

	if opts[:enumtrusts]
		puts "Enumerating Domain Trusts...".green
		ldap_con.search( :base => @treebase, :filter => Domain.domain_info) do |entry|
			Domain.new(entry)
			Domain.current(entry)
		end
		ldap_con.search( :base => @treebase, :filter => Domain.find_trusts) do |entry|
			Domain.new(entry)
		end
		if Domain.all_domains.empty?
			puts "No Trusts".red
		else
			Domain.all_domains.each do |trust|
				puts "---------------------------"
				puts "Domain Name: #{trust.name}"
				puts "Trust Direction: #{trust.trust_direction}"
				puts "Trust Type: #{trust.trust_type}"
				puts "Trust Attributes: #{trust.trust_attributes}\n"
				puts "Relation: #{trust.relation}"
			end
		end
		puts "---------------------------"
	end

	if opts[:queryuser]
		puts "Query:#{User.find_user(opts[:queryuser])}"
		# Group.get_da_group(ldap_con, @treebase)
		rows = []
		ldap_con.search( :base => @treebase, :filter => User.find_user(opts[:queryuser])) do |entry|
			member_of = []
			ldap_con.search( :base => @treebase, :filter => User.recursive_user_memberof(entry.dn)) do |memberofs|
				# if memberofs.name[-1].to_s =~ /admin/
				# 	@admin = true
				# end
				member_of << memberofs.name
			end
			@u = User.new(entry, member_of)
		 	rows << ["Username", @u.name]
		 	rows << ["Admin", @admin]
		 	rows << ["Enabled", @u.enabled]
		 	rows << ["Logon Count", @u.logon_count]
		 	rows << ["Member Of", @u.member_of.join(", ")]
		 	rows << ["Created", @u.when_created]
		 	rows << ["Modified", @u.when_changed]
		 	rows << ["Last Incorrect Password Attempt", @u.bad_password_time]
		 	rows << ["Expires", @u.account_expires]
		 	rows << ["Last Logon", @u.last_logon]
		 	rows << ["Description", @u.description]
		end
		puts  Terminal::Table.new :rows => rows
		if @u.nil?
			puts "Couldn't find user: #{opts[:queryuser]}".red
		end
	end

	if opts[:enumgroups]
		puts "Enumerating Groups".green
		rows = []
		ldap_con.search( :base => @treebase, :filter => Group.find_all_groups()) do |entry|
			print (".").to_s.green
			group = Group.new(entry, nil)
			ldap_con.search( :base => @treebase, :filter => Group.recursive_memberof(group)) do |memberofs|
				group.members << memberofs.name
				User.new(memberofs, memberofs.memberof)
			end
			rows << [group.name, (group.admin ? "True".green : "False".red), group.members.count]
		end
		puts  Terminal::Table.new :headings => ["Group Name", "Admin Group", "Number of Members"], :rows => rows
	end

	if opts[:enumallusers]
		if !opts[:nonestedmembers]
		puts "Hmm, enumerating the whole domain with nested group enumeration...that could take a while, maybe try --nonestedmembers".yellow
		end
		rows = []
			ldap_con.search( :base => @treebase, :filter => User.find_all_users) do |entry|
				print (".").to_s.green
				member_of = []
				# pp entry
				## You need to implement a flag to boolean nested and non nested enumeration
				if !opts[:nonestedmembers]
					ldap_con.search( :base => @treebase, :filter => User.recursive_user_memberof(entry.dn)) do |memberofs|
						member_of << memberofs.name
					end
				elsif
						memberof = entry.memberof rescue nil
						unless memberof.nil?
						entry.memberof.to_a.each do |memberofs|
							member_of << memberofs.split(",")[0].gsub(/CN=/,'')
						end
					end
				end
				user = User.new(entry, member_of)
				# puts "Name: #{user.name} - Admin:" + (user.admin ? " Trusere".green : " False".red) + (user.description ? "- Description: #{user.description}".yellow : "- Description: None".green)
				rows << [user.name, (user.admin ? "True".green : "False".red), (user.description ? "Exists".yellow : "None".green)]
			end
			puts  Terminal::Table.new :headings => ["Username", "Admin", "Description"], :rows => rows
	end

	if opts[:domaincomputers]
		rows = []
		if opts[:domaincomputers] == "all"
			filter = Computer.find_all_computers
		elsif opts[:domaincomputers] == "workstations"
			filter = Computer.find_all_workstations
		elsif opts[:domaincomputers] == "servers"
			filter = Computer.find_all_servers
		elsif opts[:domaincomputers] == "domaincontrollers"
			filter = Computer.find_all_domaincontrollers
		end
		ldap_con.search( :base => @treebase, :filter => filter) do |entry|
			Computer.new(entry)
		end
		Computer.all_computers.each do |computer|
			rows << [computer.cn, computer.os, computer.sp, computer.dns, computer.ip]
		end
		table = Terminal::Table.new :headings => ["Name", "Operating System", "Service Pack", "DNS", "IP Address"], :rows => rows
		puts table
	end


	if opts[:groupname]
		ldap_con.search( :base => @treebase, :filter => Net::LDAP::Filter.construct("(name=#{opts[:groupname]}))")) do |entry|
			member_obj = entry.member rescue []
			Group.new(entry,member_obj)
		end
		Group.find_group(opts[:groupname])

		unless Group.all_groups.empty?
			puts "Found Group: #{opts[:groupname]}".green
		else
			puts "Unable to find group \"#{opts[:groupname]}\", is the TLD correct?".red
			exit
		end
		# use the memberof LDAP query to pull back all users and nested users in the group
		ldap_con.search( :base => @treebase, :filter => Group.recursive_memberof(Group.search_group)) do |entry|
			member_of = []
			entry.memberof.to_a.each do |memberofs|
				member_of << memberofs.split(",")[0].gsub(/CN=/,'')
			end
			user = User.new(entry, member_of)
			puts "Name: #{user.name} - admin: " + (user.admin ? "True".green : "False".red)
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
			User.all_users.uniq! {|user| user.name}
			unless User.all_users.empty?
				if opts[:enumallusers]
					cmd = TTY::Command.new(printer: :quiet)
					connection = cmd.run("python /usr/local/bin/secretsdump.py #{opts[:domain]}/#{opts[:username]}\:\"#{opts[:password]}\"\@#{opts[:host]} -just-dc-ntlm")
					connection.each do |line|
						if line.include? ":::"
							User.all_hash(line)
						end
					end
				else
					User.all_users.each do |user|
						output = ''
						cmd = TTY::Command.new(output: output, printer: :quiet)
						#this path is correct in both OSX and Kali
						connection = cmd.run("python /usr/local/bin/secretsdump.py \'#{opts[:domain]}/#{opts[:username]}\:#{opts[:password]}\'\@#{opts[:host]} -just-dc-ntlm -just-dc-user \"#{opts[:domain]}/#{user.name}\"")
						if connection.out =~ /\:\:\:$/
							user.hash = connection.out.split("\n")[4]
							user.hash_type = User.hash_type(user.hash)
							puts user.hash
						elsif connection.out =~ /[-] ERROR_DS_NAME_ERROR_NOT_FOUND: Name translation/
							user.hash = "EMPTY"
							user.hash_type = "EMPTY"
						else		
						puts connection.out				
							# puts "Not enough privilege, aborting hashdump".red
							# throw :nopriv
						end
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
end

#Some CSV output
if opts[:csv]
	puts "Writing CSV Files".green
	unless User.all_users.empty?
		CSV.open("users_output.csv", "w+") do |csv|
			csv << ["Username", "Admin-like", "Enabled", "Logon Count", "Description", "Created", "Changed", "Password Last Changed", "Last bad password attempt", "Expires", "Hash", "Hash Type", "Password", "Member of", "Found Externally"]
			User.all_users.each do |user|
				if user.member_of.nil? or user.member_of.empty?
					member_of = []
				else
					member_of = user.member_of
				end
				if opts[:redacted]
					if user.password.nil?
						password = "Not Cracked"
					else
						password = "Cracked"
					end
					hash = "REDACTED"
				else
					password = user.password
					hash = user.hash
				end
				csv << [user.name, user.admin, user.enabled, user.logon_count, user.description, user.when_created, user.when_changed, user.pwdlastset, user.bad_password_time, user.account_expires, hash, user.hash_type, password, member_of.join(", "), user.external]
			end
		end
	end
	unless Group.all_groups.empty?
		CSV.open("allgroups_output.csv", "w+") do |csv|
			csv << ["Group", "Admin?", "Members"]
			Group.all_groups.each do |group|
				csv << [group.name, group.admin, group.members.join(", ")]
			end
		end
	end

	unless Computer.all_computers.empty?
		CSV.open("allcomputers_output.csv", "w+") do |csv|
			csv << ["Name","OS", "Service Pack","DNS","IP"]
			Computer.all_computers.each do |computer|
				csv << [computer.cn, computer.os, computer.sp, computer.dns, computer.ip]
			end
		end
	end

	unless Domain.all_domains.empty?
		CSV.open("alldomains_output.csv", "w+") do |csv|
			csv << ["Name","Trust Direction","Trust Type","Trust Attributes", "Relation"]
			Domain.all_domains.each do |domain|
				csv << [domain.name, domain.trust_direction, domain.trust_type, domain.trust_attributes, domain.relation]
			end
		end
	end

	if opts[:groupname]
		unless User.all_users.empty?
			CSV.open("group_link.csv", "w+") do |csv|
				csv << ["Username", "Group", "Linked Group", "Logon Count", "Hash", "Hash Type", "Password"]
				User.all_users.each do |user|
					csv << [user.name, opts[:groupname],user.link, user.logon_count, user.hash, user.hash_type, user.password]
				end
			end
		end
	end
end

unless opts[:restore]
	write_logs
end
