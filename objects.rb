

#Forest has many domains, domains has many computer,users and groups.


class Domain
	attr_accessor :name, :cn, :trust_direction, :trust_type, :trust_attributes, :relation 
	@@domains = []
	def initialize(entry)
		@name = entry.name.reduce.to_s rescue nil
		@cn = entry.cn.entries.reduce.to_s rescue nil
		@trust_direction = Domain.trust_direction(entry.trustdirection)
		@trust_type = Domain.trust_type(entry.trusttype)
		@trust_attributes = Domain.trust_attributes(entry.trustattributes)
		@relation = Domain.relation(@cn)
		@@domains << self
	end

	def self.current(entry)
		@@current = entry.dn.split(/,DC=/).join(".").sub!("DC=","")
	end


	def self.current_domain
		@@current
	end

	def self.relation(cn)
		@@current.downcase!
		cn.downcase!
		if cn.include? @@current
			"Child"
		elsif @@current.include? cn
			"Parent"
		else
			"No relation"
		end
	end

	def self.find_trusts
		Net::LDAP::Filter.construct("(objectCategory=trusteddomain)")
	end

	def self.domain_info
		Net::LDAP::Filter.construct("(objectCategory=domain)")
	end

	def self.trust_direction(direction) 
		e = direction.to_a.reduce.to_i
		if e == 1
			"Inbound"
		elsif e == 2
			"Outbound"
		elsif e == 3
			"Bidirectional"
		elsif e == "default"
			"NA"
		end
	end

	def self.trust_type(type)
		e = type.to_a.reduce.to_i
		if e  == 1
			"Windows NT"
		elsif e == 2
			"Active Directory"
		elsif e == 3
			"Kerberos Realm"
		elsif e == 4
			"DCE"
		elsif e == "default"
			"N/A"
		end
	end

	def self.trust_attributes(attributes)
		e = attributes.map {|i| i.to_i}
		if e.include? 1
			"Not transitive"
		elsif e.include? 2
			"Only 2000 & Above can use this trust"
		elsif e.include? 4
			"SID Filtering Enabled"
		elsif e.include? 8
			"Forest Trust"
		elsif e.include? 16
			"Cross-org” trust with selective authentication enabled"
		elsif e.include? 32
			"Forest-internal"
		elsif e.include? 64
			"This is a forest trust with SIDHistory enabled"
		end
	end

	def self.all_domains
		@@domains
	end
end

class Group
	attr_accessor :name, :dn, :members, :admin, :member_objects
	@@groups = []
	@@group = nil

	def initialize(entry, member_obj)
		@name = entry.cn.entries.reduce.to_s rescue nil
		@dn = entry.dn
		@members = member_obj = []
		@member_objects = nil
		@admin = Group.is_admin(entry.admincount.entries.reduce.to_i) rescue false
		@@groups << self
	end

	def self.is_admin(value)
		if value == 1
			true
		else
			false
		end
	end

	def self.recursive_memberof(group)
	 	dn =  group.dn
	 	Net::LDAP::Filter.construct("(&(objectCategory=Person)(sAMAccountName=*)(memberOf:1.2.840.113556.1.4.1941:=#{dn}))")
	end

	def self.find_all_groups
		Net::LDAP::Filter.construct("(|(objectCategory=Group)(objectCategory=OU))")
	end

	def self.all_groups
		@@groups
	end

	def self.find_group(grpname)
		#This function has to be run first before the search_group function can be used...obviously
		@@group = @@groups.find {|i|  i.name =~ /#{grpname}/im }
	end

	def self.search_group
		@@group
	end
end

class User
	#There are a lot of attributes here as we have to pull out lots of crap from LDAP
	attr_accessor :name, :hash, :hash_type, :member_of, :link, :logon_count, :admin, :description, :password
	attr_accessor :enabled, :when_created, :when_changed, :bad_password_time, :last_logon, :pwdlastset, :account_expires
	@@users = []
	@@user_count = 0

	def initialize(entry, member_of)
		@name = entry.samaccountname.entries.reduce rescue nil
		@hash = hash
		@hash_type = hash_type
		@password = nil
		@member_of = member_of
		@link = link
		@logon_count = entry.logoncount.entries.reduce rescue nil
		@admin = User.isadmin(entry)
		@enabled = User.account_enabled(entry)
		@description = entry.description.entries.reduce rescue nil
		#time related
		@when_created = User.windows_time_two(entry.whencreated.entries.reduce) rescue nil
		@when_changed = User.windows_time_two(entry.whenchanged.entries.reduce) rescue nil
		@bad_password_time = User.windows_time(entry.badpasswordtime.entries.reduce) rescue nil
		@last_logon = User.windows_time(entry.lastlogon.entries.reduce) rescue nil
		@pwdlastset = User.windows_time(entry.pwdlastset.entries.reduce) rescue nil
		@account_expires = User.windows_time(entry.accountexpires.entries.reduce) rescue nil
		#class related
		@@users << self
		@@user_count += 1
	end

	def self.all_users
		@@users
	end

	def self.find_user(username)
		Net::LDAP::Filter.construct("(&(sAMAccountName=#{username}))")
	end

	def self.find_admin
		#Huh, neat
		Net::LDAP::Filter.construct("(&(objectCategory=Person)(admincount=1))")
	end

	def self.recursive_user_memberof(dn)
		Net::LDAP::Filter.construct("(member:1.2.840.113556.1.4.1941:=#{dn})")
	end

	def self.find_all_users
		Net::LDAP::Filter.construct("(objectCategory=Person)")
	end

	def self.hash_type(user)
		user = user rescue "EMPTY"
		if user.hash.include? 'aad3b435b51404eeaad3b435b51404ee'
			user.hash_type = "NTML"
		else
			puts "LM".red
			user.hash_type = "LM"
		end
	end

	def self.cracked(line)
		username = line.split(":")[0].split("\\")[1]
		password = line.split(":")[1]
		if i = User.all_users.find {|u| u.name == username }
			i.password = password
		end
	end

	def self.all_hash(line)
		username = line.split(":")[0].split("\\")[1] rescue ""
		# hash = line.split(":")[2,3].join(":") rescue ""
		if i = User.all_users.find {|u| u.name == username }
			i.hash = line
		end
	end

	def self.isadmin(entry)
		begin
			if entry.admincount.entries.reduce.to_i == 1
				true
			else
				false
			end
		rescue
			false
		end
	end


	def self.account_enabled(entry)
			begin
			if ["512", "66048"].include? (entry.useraccountcontrol.entries.reduce.to_s) #Ugly, isnt it?
				true
			else
				false
			end
		rescue
			false
		end
	end

	def self.windows_time(date)
		begin
			windowsTime = date.to_i || 128976739610612366 #default value
			unixTime = windowsTime/10000000-11644473600
			date = Time.at(unixTime) #stupid date time
			if [30828 ,1600, 1601].include?(date.year)
				return "Never"
			else
				return date.to_date.strftime
			end
		rescue
			return "Error"
		end
	end

	def self.windows_time_two(date)
		begin
			date = Date.strptime(date,"%Y%m%d%H%M%S")
			if [30828 ,1600, 1602].include?(date.year)
				return "Never"
			else
				return date.strftime
			end
		rescue
			return "Error"
		end
	end
end

class Computer
	attr_accessor :cn, :os, :dns, :ip, :sp
	@@computers = []

	def initialize(entry)
		@cn = entry.cn.entries.reduce rescue nil
		@os = entry.operatingsystem.entries.reduce rescue nil
		@dns = entry.dnshostname.entries.reduce rescue nil
		@ip = entry.networkaddress.entries.reduce rescue "Not specified"
		@sp  = entry.operatingsystemservicepack.entries.reduce rescue nil
		@@computers << self
	end

	def self.all_computers
		@@computers
	end

	def self.find_all_computers
		Net::LDAP::Filter.construct("(&(&(objectCategory=computer)))")
	end

	def self.find_all_workstations #This is an annoying function as it require a NOT statement, which isnt even a ruby not!
		compfilter = Net::LDAP::Filter.eq("Objectcategory", "Computer")
		notfilter = ~ Net::LDAP::Filter.eq( "operatingSystem", "Windows Server*" )
		filter = Net::LDAP::Filter.join(compfilter, notfilter)
	end

	def self.find_all_servers
		Net::LDAP::Filter.construct("(&(&(objectCategory=computer)(operatingSystem=Windows Server*)))")
	end

	def self.find_all_domaincontrollers
		Net::LDAP::Filter.construct("(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))")
	end
end