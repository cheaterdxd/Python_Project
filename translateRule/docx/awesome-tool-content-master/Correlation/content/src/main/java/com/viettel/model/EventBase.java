package com.viettel.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class EventBase implements Serializable {
    String source_log;
    String type;
    String category;
    String sub_category;
    String classify;
    String plugin_id;
    String client_id;
    String sensor_id;
    String server_id;
    String device_id;
    String src;
    Integer spt;
    String dst;
    Integer dpt;
    String proto;
    String ip;
    ArrayList<String> ips;
    Long total_packets;
    String connection_state;
    String payload_printable;
    String status;
    String url;
    String uri;
    String hostname;
    String useragent;
    String method;
    Integer length;
    String referer;
    String qtype;
    String qtype2;
    String service;
    String service_info;
    String module_name;
    String module_type;
    Integer pid;
    String filename;
    String cwd;
    String fullpath;
    String context;
    String fullcmd;
    String params;
    String reference;
    String link;
    String app_name;
    String targetpath;
    String filetype;
    String md5;
    String suser;
    String duser;
    String uid;
    String shell;
    String domain;
    String workgroup;
    String mac_addr;
    String serial_number;
    String mac_vendor;
    String os_name;
    String os_platform;
    String email;
    String mailfrom;
    ArrayList<String> mailto;
    String subject;
    String baseline_item;
    String current_desc;
    String old_desc;
    Long current_time;
    Long old_time;
    String session;
    String opcode;
    String typetcap;
    String oid;
    String callingssn;
    String callinggt;
    String calledssn;
    String calledgt;
    String imsi;
    String msisdn;
    String hlr;
    String gsmscf;
    String lociinfo;
    String threshold;
    String count;
    String starttime;
    String typemap;
    ArrayList<String> actor_hashes;
    ArrayList<String> reference_hashes;
    ArrayList<String> tag_comments;
    ArrayList<Integer> tag_levels;
    String program_name;
    String user;
    String location;
    String source_service_name;
    String root_directory;
    String action;
    String state;
    String network_zone;
    String full_log;
    String src_cc;
    String dst_cc;
    String dst_ips;
    String graphic;
    String attack_id;
    String group;
    String site_id;
    String connection_allowed;
    String connection_denied;
    String packet_in;
    String packet_out;
    String bit_in;
    String bit_out;
    String concurrent_connection;
    String conntrack;
    String request_allowed;
    String request_denied;
    String extra_data;
    String log_parser;
    String application;
    String input_plugin;
    String access;
    String address;
    String base;
    String computer_name;
    String create_time;
    String file_version;
    String group_id;
    String process;
    String process_name;
    String product;
    String raw_json;
    String raw_str;
    String root_dir;
    String sha1;
    String sha256;
    String size;
    String client_ip;
    String cmd;
    String file_path;
    String host;
    String log_file;
    String log_source;
    String member;
    String module;
    String msg;
    String ni;
    String payload;
    String policy_id;
    String priority;
    String program;
    String reason;
    String referrer;
    String rev;
    String severity_label;
    String source;
    String source_name;
    String source_service;
    String target;
    String attacker;
    String attacker_cc;
    String attacker_cc3;
    String attacker_city;
    Double attacker_latitude;
    Double attacker_longtitude;
    String attacker_country_name;
    String target_cc;
    String target_cc3;
    String target_city;
    Double target_latitude;
    Double target_longtitude;
    String target_country_name;
    String src_cc3;
    String src_city;
    Double src_latitude;
    Double src_longtitude;
    String src_country_name;
    String dst_cc3;
    String dst_city;
    Double dst_latitude;
    Double dst_longtitude;
    String dst_country_name;
    String tmp_object;
    String tmp_object_type;
    String parent_fullpath;
    String parent_fullcmd;
    String attack_type;
    String policy_name;
    String user_id;
    String obj_name;
    String owner;
    String logon_type;
    String process_id;
    String share_name;
    String start_type;
    String service_type;
    String param1;
    String param2;
    String param3;
    String param4;
    String fsrc;
    String customer_group;
    String log_channel_name;
    String log_provider_name;
    String attack_tactic;
    String attack_technique;
    String target_process_id;
    String source_process_id;
    String target_thread_id;
    String target_user_name;
    String target_domain_name;
    String source_domain_name;
    String start_function;
    String file_signed;
    String file_signature;
    String wmi_event_type;
    String wmi_operation;
    String wmi_user;
    String wmi_name;
    String wmi_type;
    String wmi_destination;
    String wmi_event_namespace;
    String wmi_query;
    String wmi_superchar;
    String wmi_consumer;
    String wmi_filter;
    String user_name;
    String user_logon_id;
    String user_logon_guid;
    String net_source_host_name;
    String net_target_host_name;
    String net_source_port_name;
    String net_target_port_name;
    String net_source_is_ipv6;
    String net_target_is_ipv6;
    String reg_target_object;
    String reg_value_name;
    String reg_event_type;
    String reg_old_value_type;
    String reg_new_value_type;
    String reg_old_value;
    String reg_new_value;
    String reg_desired_access;
    String reg_value_data;
    String reg_value_type;
    String logon_process_name;
    String task_name;
    String task_content;
    String service_target_name;
    String service_source_name;
    String service_target_file_path;
    String hash_md5;
    String hash_sha256;
    String event_log_id;
    String target_process_path;
    String target_process_guid;
    String source_process_path;
    String source_process_guid;
    String target_commandline;
    String source_commandline;
    String target_current_directory;
    String desired_access;
    String file_status;
    String file_shared_access;
    String file_attributes;
    String file_description;
    String file_product;
    String file_company;
    String file_hash_md5;
    String file_hash_sha256;
    String file_signature_expried;
    String user_sid;
    String user_target_sid;
    String user_privilege_list;
    String user_sam_account_name;
    String user_display_name;
    String user_principal_name;
    String user_home_directory;
    String user_home_path;
    String user_script_path;
    String user_profile_path;
    String user_work_stations;
    String user_password_last_set;
    String user_account_expires;
    String user_primary_group_id;
    String user_allowed_to_delegate_to;
    String user_old_uac_value;
    String user_new_uac_value;
    String user_account_control;
    String user_parameters;
    String user_sid_history;
    String user_logon_hours;
    String net_initiated;
    String net_flag;
    String net_extra_data;
    String net_target_outbound_domain_name;
    String net_target_outbound_user_name;
    String layer_name;
    String remote_user_id;
    String remote_machine_id;
    String service_old_start_type;
    String service_new_start_type;
    String service_account;
    String authentication_package_name;
    String workstation_name;
    String lm_package_name;
    String restricted_admin_mode;
    String virtual_account;
    String logon_failure_reason;
    String contents;
    String logon_status;
    Integer time_old_creation;
    Integer time_new_creation;
    Integer buffer_leng;
    Integer net_inbound_count;
    Integer net_outbound_count;
    Long reg_value_data_leng;
    Integer key_length;
    String logon_substatus;
    String command;
    String command_data;
    Integer threats;
    String alert_type;
    String relative_target_name;
    String subtype;
    String resource_attributes;
    String src_mac;
    String level;
    Long uptime;
    String full_request;
    String signature_raw;
    String user_agent;
    String tenant;
    String administrator;
    String operation;
    String machine;
    String objecttype;
    String fieldschanges;
    String function_name;
    String time_generated;
    Long local_timestamp;
    String volumes;
    String object_type;
    String old_value;
    String new_value;
    String object_value_name;
    String host_application;
    String host_name;
    String script_name;
    String log_name;
    String group_name;
    String agent_id;
    String rule;
    String target_hostname;
    String query;
    String actor;
    String group_domain;
    String arn;
    String session_issuer_type;
    String event_source;
    String event_name;
    String request_attribute;
    String request_container_command;
    String response_access_key_user_name;
    String response_user_password;
    String response_puiblic_accessible;
    String event_type;
    String signature_id;
    Map<String, String> unknownFields;
    String script_content;
    String organization_group;
    String timestamp;
    String powershell_scriptblock_text;
    String device_product;
    String object;
    String file_originalname;
    String parent_file_product;


    public EventBase() {
    }

    public String getSource_log() {
        return source_log;
    }

    public void setSource_log(String source_log) {
        this.source_log = source_log;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getSub_category() {
        return sub_category;
    }

    public void setSub_category(String sub_category) {
        this.sub_category = sub_category;
    }

    public String getClassify() {
        return classify;
    }

    public void setClassify(String classify) {
        this.classify = classify;
    }

    public String getPlugin_id() {
        return plugin_id;
    }

    public void setPlugin_id(String plugin_id) {
        this.plugin_id = plugin_id;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    public String getSensor_id() {
        return sensor_id;
    }

    public void setSensor_id(String sensor_id) {
        this.sensor_id = sensor_id;
    }

    public String getServer_id() {
        return server_id;
    }

    public void setServer_id(String server_id) {
        this.server_id = server_id;
    }

    public String getDevice_id() {
        return device_id;
    }

    public void setDevice_id(String device_id) {
        this.device_id = device_id;
    }

    public String getSrc() {
        return src;
    }

    public void setSrc(String src) {
        this.src = src;
    }

    public Integer getSpt() {
        return spt;
    }

    public void setSpt(Integer spt) {
        this.spt = spt;
    }

    public String getDst() {
        return dst;
    }

    public void setDst(String dst) {
        this.dst = dst;
    }

    public Integer getDpt() {
        return dpt;
    }

    public void setDpt(Integer dpt) {
        this.dpt = dpt;
    }

    public String getProto() {
        return proto;
    }

    public void setProto(String proto) {
        this.proto = proto;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public ArrayList<String> getIps() {
        return ips;
    }

    public void setIps(ArrayList<String> ips) {
        this.ips = ips;
    }

    public Long getTotal_packets() {
        return total_packets;
    }

    public void setTotal_packets(Long total_packets) {
        this.total_packets = total_packets;
    }

    public String getConnection_state() {
        return connection_state;
    }

    public void setConnection_state(String connection_state) {
        this.connection_state = connection_state;
    }

    public String getPayload_printable() {
        return payload_printable;
    }

    public void setPayload_printable(String payload_printable) {
        this.payload_printable = payload_printable;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getUseragent() {
        return useragent;
    }

    public void setUseragent(String useragent) {
        this.useragent = useragent;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public Integer getLength() {
        return length;
    }

    public void setLength(Integer length) {
        this.length = length;
    }

    public String getReferer() {
        return referer;
    }

    public void setReferer(String referer) {
        this.referer = referer;
    }

    public String getQtype() {
        return qtype;
    }

    public void setQtype(String qtype) {
        this.qtype = qtype;
    }

    public String getQtype2() {
        return qtype2;
    }

    public void setQtype2(String qtype2) {
        this.qtype2 = qtype2;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getService_info() {
        return service_info;
    }

    public void setService_info(String service_info) {
        this.service_info = service_info;
    }

    public String getModule_name() {
        return module_name;
    }

    public void setModule_name(String module_name) {
        this.module_name = module_name;
    }

    public String getModule_type() {
        return module_type;
    }

    public void setModule_type(String module_type) {
        this.module_type = module_type;
    }

    public Integer getPid() {
        return pid;
    }

    public void setPid(Integer pid) {
        this.pid = pid;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getCwd() {
        return cwd;
    }

    public void setCwd(String cwd) {
        this.cwd = cwd;
    }

    public String getFullpath() {
        return fullpath;
    }

    public void setFullpath(String fullpath) {
        this.fullpath = fullpath;
    }

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }

    public String getFullcmd() {
        return fullcmd;
    }

    public void setFullcmd(String fullcmd) {
        this.fullcmd = fullcmd;
    }

    public String getParams() {
        return params;
    }

    public void setParams(String params) {
        this.params = params;
    }

    public String getReference() {
        return reference;
    }

    public void setReference(String reference) {
        this.reference = reference;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public String getApp_name() {
        return app_name;
    }

    public void setApp_name(String app_name) {
        this.app_name = app_name;
    }

    public String getTargetpath() {
        return targetpath;
    }

    public void setTargetpath(String targetpath) {
        this.targetpath = targetpath;
    }

    public String getFiletype() {
        return filetype;
    }

    public void setFiletype(String filetype) {
        this.filetype = filetype;
    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getSuser() {
        return suser;
    }

    public void setSuser(String suser) {
        this.suser = suser;
    }

    public String getDuser() {
        return duser;
    }

    public void setDuser(String duser) {
        this.duser = duser;
    }

    public String getUid() {
        return uid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getShell() {
        return shell;
    }

    public void setShell(String shell) {
        this.shell = shell;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getWorkgroup() {
        return workgroup;
    }

    public void setWorkgroup(String workgroup) {
        this.workgroup = workgroup;
    }

    public String getMac_addr() {
        return mac_addr;
    }

    public void setMac_addr(String mac_addr) {
        this.mac_addr = mac_addr;
    }

    public String getSerial_number() {
        return serial_number;
    }

    public void setSerial_number(String serial_number) {
        this.serial_number = serial_number;
    }

    public String getMac_vendor() {
        return mac_vendor;
    }

    public void setMac_vendor(String mac_vendor) {
        this.mac_vendor = mac_vendor;
    }

    public String getOs_name() {
        return os_name;
    }

    public void setOs_name(String os_name) {
        this.os_name = os_name;
    }

    public String getOs_platform() {
        return os_platform;
    }

    public void setOs_platform(String os_platform) {
        this.os_platform = os_platform;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getMailfrom() {
        return mailfrom;
    }

    public void setMailfrom(String mailfrom) {
        this.mailfrom = mailfrom;
    }

    public ArrayList<String> getMailto() {
        return mailto;
    }

    public void setMailto(ArrayList<String> mailto) {
        this.mailto = mailto;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getBaseline_item() {
        return baseline_item;
    }

    public void setBaseline_item(String baseline_item) {
        this.baseline_item = baseline_item;
    }

    public String getCurrent_desc() {
        return current_desc;
    }

    public void setCurrent_desc(String current_desc) {
        this.current_desc = current_desc;
    }

    public String getOld_desc() {
        return old_desc;
    }

    public void setOld_desc(String old_desc) {
        this.old_desc = old_desc;
    }

    public Long getCurrent_time() {
        return current_time;
    }

    public void setCurrent_time(Long current_time) {
        this.current_time = current_time;
    }

    public Long getOld_time() {
        return old_time;
    }

    public void setOld_time(Long old_time) {
        this.old_time = old_time;
    }

    public String getSession() {
        return session;
    }

    public void setSession(String session) {
        this.session = session;
    }

    public String getOpcode() {
        return opcode;
    }

    public void setOpcode(String opcode) {
        this.opcode = opcode;
    }

    public String getTypetcap() {
        return typetcap;
    }

    public void setTypetcap(String typetcap) {
        this.typetcap = typetcap;
    }

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public String getCallingssn() {
        return callingssn;
    }

    public void setCallingssn(String callingssn) {
        this.callingssn = callingssn;
    }

    public String getCallinggt() {
        return callinggt;
    }

    public void setCallinggt(String callinggt) {
        this.callinggt = callinggt;
    }

    public String getCalledssn() {
        return calledssn;
    }

    public void setCalledssn(String calledssn) {
        this.calledssn = calledssn;
    }

    public String getCalledgt() {
        return calledgt;
    }

    public void setCalledgt(String calledgt) {
        this.calledgt = calledgt;
    }

    public String getImsi() {
        return imsi;
    }

    public void setImsi(String imsi) {
        this.imsi = imsi;
    }

    public String getMsisdn() {
        return msisdn;
    }

    public void setMsisdn(String msisdn) {
        this.msisdn = msisdn;
    }

    public String getHlr() {
        return hlr;
    }

    public void setHlr(String hlr) {
        this.hlr = hlr;
    }

    public String getGsmscf() {
        return gsmscf;
    }

    public void setGsmscf(String gsmscf) {
        this.gsmscf = gsmscf;
    }

    public String getLociinfo() {
        return lociinfo;
    }

    public void setLociinfo(String lociinfo) {
        this.lociinfo = lociinfo;
    }

    public String getThreshold() {
        return threshold;
    }

    public void setThreshold(String threshold) {
        this.threshold = threshold;
    }

    public String getCount() {
        return count;
    }

    public void setCount(String count) {
        this.count = count;
    }

    public String getStarttime() {
        return starttime;
    }

    public void setStarttime(String starttime) {
        this.starttime = starttime;
    }

    public String getTypemap() {
        return typemap;
    }

    public void setTypemap(String typemap) {
        this.typemap = typemap;
    }

    public ArrayList<String> getActor_hashes() {
        return actor_hashes;
    }

    public void setActor_hashes(ArrayList<String> actor_hashes) {
        this.actor_hashes = actor_hashes;
    }

    public ArrayList<String> getReference_hashes() {
        return reference_hashes;
    }

    public void setReference_hashes(ArrayList<String> reference_hashes) {
        this.reference_hashes = reference_hashes;
    }

    public ArrayList<String> getTag_comments() {
        return tag_comments;
    }

    public void setTag_comments(ArrayList<String> tag_comments) {
        this.tag_comments = tag_comments;
    }

    public ArrayList<Integer> getTag_levels() {
        return tag_levels;
    }

    public void setTag_levels(ArrayList<Integer> tag_levels) {
        this.tag_levels = tag_levels;
    }

    public String getProgram_name() {
        return program_name;
    }

    public void setProgram_name(String program_name) {
        this.program_name = program_name;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getSource_service_name() {
        return source_service_name;
    }

    public void setSource_service_name(String source_service_name) {
        this.source_service_name = source_service_name;
    }

    public String getRoot_directory() {
        return root_directory;
    }

    public void setRoot_directory(String root_directory) {
        this.root_directory = root_directory;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getNetwork_zone() {
        return network_zone;
    }

    public void setNetwork_zone(String network_zone) {
        this.network_zone = network_zone;
    }

    public String getFull_log() {
        return full_log;
    }

    public void setFull_log(String full_log) {
        this.full_log = full_log;
    }

    public String getSrc_cc() {
        return src_cc;
    }

    public void setSrc_cc(String src_cc) {
        this.src_cc = src_cc;
    }

    public String getDst_cc() {
        return dst_cc;
    }

    public void setDst_cc(String dst_cc) {
        this.dst_cc = dst_cc;
    }

    public String getDst_ips() {
        return dst_ips;
    }

    public void setDst_ips(String dst_ips) {
        this.dst_ips = dst_ips;
    }

    public String getGraphic() {
        return graphic;
    }

    public void setGraphic(String graphic) {
        this.graphic = graphic;
    }

    public String getAttack_id() {
        return attack_id;
    }

    public void setAttack_id(String attack_id) {
        this.attack_id = attack_id;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

    public String getSite_id() {
        return site_id;
    }

    public void setSite_id(String site_id) {
        this.site_id = site_id;
    }

    public String getConnection_allowed() {
        return connection_allowed;
    }

    public void setConnection_allowed(String connection_allowed) {
        this.connection_allowed = connection_allowed;
    }

    public String getConnection_denied() {
        return connection_denied;
    }

    public void setConnection_denied(String connection_denied) {
        this.connection_denied = connection_denied;
    }

    public String getPacket_in() {
        return packet_in;
    }

    public void setPacket_in(String packet_in) {
        this.packet_in = packet_in;
    }

    public String getPacket_out() {
        return packet_out;
    }

    public void setPacket_out(String packet_out) {
        this.packet_out = packet_out;
    }

    public String getBit_in() {
        return bit_in;
    }

    public void setBit_in(String bit_in) {
        this.bit_in = bit_in;
    }

    public String getBit_out() {
        return bit_out;
    }

    public void setBit_out(String bit_out) {
        this.bit_out = bit_out;
    }

    public String getConcurrent_connection() {
        return concurrent_connection;
    }

    public void setConcurrent_connection(String concurrent_connection) {
        this.concurrent_connection = concurrent_connection;
    }

    public String getConntrack() {
        return conntrack;
    }

    public void setConntrack(String conntrack) {
        this.conntrack = conntrack;
    }

    public String getRequest_allowed() {
        return request_allowed;
    }

    public void setRequest_allowed(String request_allowed) {
        this.request_allowed = request_allowed;
    }

    public String getRequest_denied() {
        return request_denied;
    }

    public void setRequest_denied(String request_denied) {
        this.request_denied = request_denied;
    }

    public String getExtra_data() {
        return extra_data;
    }

    public void setExtra_data(String extra_data) {
        this.extra_data = extra_data;
    }

    public String getLog_parser() {
        return log_parser;
    }

    public void setLog_parser(String log_parser) {
        this.log_parser = log_parser;
    }

    public String getApplication() {
        return application;
    }

    public void setApplication(String application) {
        this.application = application;
    }

    public String getInput_plugin() {
        return input_plugin;
    }

    public void setInput_plugin(String input_plugin) {
        this.input_plugin = input_plugin;
    }

    public String getAccess() {
        return access;
    }

    public void setAccess(String access) {
        this.access = access;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getBase() {
        return base;
    }

    public void setBase(String base) {
        this.base = base;
    }

    public String getComputer_name() {
        return computer_name;
    }

    public void setComputer_name(String computer_name) {
        this.computer_name = computer_name;
    }

    public String getCreate_time() {
        return create_time;
    }

    public void setCreate_time(String create_time) {
        this.create_time = create_time;
    }

    public String getFile_version() {
        return file_version;
    }

    public void setFile_version(String file_version) {
        this.file_version = file_version;
    }

    public String getGroup_id() {
        return group_id;
    }

    public void setGroup_id(String group_id) {
        this.group_id = group_id;
    }

    public String getProcess() {
        return process;
    }

    public void setProcess(String process) {
        this.process = process;
    }

    public String getProcess_name() {
        return process_name;
    }

    public void setProcess_name(String process_name) {
        this.process_name = process_name;
    }

    public String getProduct() {
        return product;
    }

    public void setProduct(String product) {
        this.product = product;
    }

    public String getRaw_json() {
        return raw_json;
    }

    public void setRaw_json(String raw_json) {
        this.raw_json = raw_json;
    }

    public String getRaw_str() {
        return raw_str;
    }

    public void setRaw_str(String raw_str) {
        this.raw_str = raw_str;
    }

    public String getRoot_dir() {
        return root_dir;
    }

    public void setRoot_dir(String root_dir) {
        this.root_dir = root_dir;
    }

    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getSize() {
        return size;
    }

    public void setSize(String size) {
        this.size = size;
    }

    public String getClient_ip() {
        return client_ip;
    }

    public void setClient_ip(String client_ip) {
        this.client_ip = client_ip;
    }

    public String getCmd() {
        return cmd;
    }

    public void setCmd(String cmd) {
        this.cmd = cmd;
    }

    public String getFile_path() {
        return file_path;
    }

    public void setFile_path(String file_path) {
        this.file_path = file_path;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getLog_file() {
        return log_file;
    }

    public void setLog_file(String log_file) {
        this.log_file = log_file;
    }

    public String getLog_source() {
        return log_source;
    }

    public void setLog_source(String log_source) {
        this.log_source = log_source;
    }

    public String getMember() {
        return member;
    }

    public void setMember(String member) {
        this.member = member;
    }

    public String getModule() {
        return module;
    }

    public void setModule(String module) {
        this.module = module;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public String getNi() {
        return ni;
    }

    public void setNi(String ni) {
        this.ni = ni;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getPolicy_id() {
        return policy_id;
    }

    public void setPolicy_id(String policy_id) {
        this.policy_id = policy_id;
    }

    public String getPriority() {
        return priority;
    }

    public void setPriority(String priority) {
        this.priority = priority;
    }

    public String getProgram() {
        return program;
    }

    public void setProgram(String program) {
        this.program = program;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getReferrer() {
        return referrer;
    }

    public void setReferrer(String referrer) {
        this.referrer = referrer;
    }

    public String getRev() {
        return rev;
    }

    public void setRev(String rev) {
        this.rev = rev;
    }

    public String getSeverity_label() {
        return severity_label;
    }

    public void setSeverity_label(String severity_label) {
        this.severity_label = severity_label;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getSource_name() {
        return source_name;
    }

    public void setSource_name(String source_name) {
        this.source_name = source_name;
    }

    public String getSource_service() {
        return source_service;
    }

    public void setSource_service(String source_service) {
        this.source_service = source_service;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getAttacker() {
        return attacker;
    }

    public void setAttacker(String attacker) {
        this.attacker = attacker;
    }

    public String getAttacker_cc() {
        return attacker_cc;
    }

    public void setAttacker_cc(String attacker_cc) {
        this.attacker_cc = attacker_cc;
    }

    public String getAttacker_cc3() {
        return attacker_cc3;
    }

    public void setAttacker_cc3(String attacker_cc3) {
        this.attacker_cc3 = attacker_cc3;
    }

    public String getAttacker_city() {
        return attacker_city;
    }

    public void setAttacker_city(String attacker_city) {
        this.attacker_city = attacker_city;
    }

    public Double getAttacker_latitude() {
        return attacker_latitude;
    }

    public void setAttacker_latitude(Double attacker_latitude) {
        this.attacker_latitude = attacker_latitude;
    }

    public Double getAttacker_longtitude() {
        return attacker_longtitude;
    }

    public void setAttacker_longtitude(Double attacker_longtitude) {
        this.attacker_longtitude = attacker_longtitude;
    }

    public String getAttacker_country_name() {
        return attacker_country_name;
    }

    public void setAttacker_country_name(String attacker_country_name) {
        this.attacker_country_name = attacker_country_name;
    }

    public String getTarget_cc() {
        return target_cc;
    }

    public void setTarget_cc(String target_cc) {
        this.target_cc = target_cc;
    }

    public String getTarget_cc3() {
        return target_cc3;
    }

    public void setTarget_cc3(String target_cc3) {
        this.target_cc3 = target_cc3;
    }

    public String getTarget_city() {
        return target_city;
    }

    public void setTarget_city(String target_city) {
        this.target_city = target_city;
    }

    public Double getTarget_latitude() {
        return target_latitude;
    }

    public void setTarget_latitude(Double target_latitude) {
        this.target_latitude = target_latitude;
    }

    public Double getTarget_longtitude() {
        return target_longtitude;
    }

    public void setTarget_longtitude(Double target_longtitude) {
        this.target_longtitude = target_longtitude;
    }

    public String getTarget_country_name() {
        return target_country_name;
    }

    public void setTarget_country_name(String target_country_name) {
        this.target_country_name = target_country_name;
    }

    public String getSrc_cc3() {
        return src_cc3;
    }

    public void setSrc_cc3(String src_cc3) {
        this.src_cc3 = src_cc3;
    }

    public String getSrc_city() {
        return src_city;
    }

    public void setSrc_city(String src_city) {
        this.src_city = src_city;
    }

    public Double getSrc_latitude() {
        return src_latitude;
    }

    public void setSrc_latitude(Double src_latitude) {
        this.src_latitude = src_latitude;
    }

    public Double getSrc_longtitude() {
        return src_longtitude;
    }

    public void setSrc_longtitude(Double src_longtitude) {
        this.src_longtitude = src_longtitude;
    }

    public String getSrc_country_name() {
        return src_country_name;
    }

    public void setSrc_country_name(String src_country_name) {
        this.src_country_name = src_country_name;
    }

    public String getDst_cc3() {
        return dst_cc3;
    }

    public void setDst_cc3(String dst_cc3) {
        this.dst_cc3 = dst_cc3;
    }

    public String getDst_city() {
        return dst_city;
    }

    public void setDst_city(String dst_city) {
        this.dst_city = dst_city;
    }

    public Double getDst_latitude() {
        return dst_latitude;
    }

    public void setDst_latitude(Double dst_latitude) {
        this.dst_latitude = dst_latitude;
    }

    public Double getDst_longtitude() {
        return dst_longtitude;
    }

    public void setDst_longtitude(Double dst_longtitude) {
        this.dst_longtitude = dst_longtitude;
    }

    public String getDst_country_name() {
        return dst_country_name;
    }

    public void setDst_country_name(String dst_country_name) {
        this.dst_country_name = dst_country_name;
    }

    public String getTmp_object() {
        return tmp_object;
    }

    public void setTmp_object(String tmp_object) {
        this.tmp_object = tmp_object;
    }

    public String getTmp_object_type() {
        return tmp_object_type;
    }

    public void setTmp_object_type(String tmp_object_type) {
        this.tmp_object_type = tmp_object_type;
    }

    public String getParent_fullpath() {
        return parent_fullpath;
    }

    public void setParent_fullpath(String parent_fullpath) {
        this.parent_fullpath = parent_fullpath;
    }

    public String getParent_fullcmd() {
        return parent_fullcmd;
    }

    public void setParent_fullcmd(String parent_fullcmd) {
        this.parent_fullcmd = parent_fullcmd;
    }

    public String getAttack_type() {
        return attack_type;
    }

    public void setAttack_type(String attack_type) {
        this.attack_type = attack_type;
    }

    public String getPolicy_name() {
        return policy_name;
    }

    public void setPolicy_name(String policy_name) {
        this.policy_name = policy_name;
    }

    public String getUser_id() {
        return user_id;
    }

    public void setUser_id(String user_id) {
        this.user_id = user_id;
    }

    public String getObj_name() {
        return obj_name;
    }

    public void setObj_name(String obj_name) {
        this.obj_name = obj_name;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getLogon_type() {
        return logon_type;
    }

    public void setLogon_type(String logon_type) {
        this.logon_type = logon_type;
    }

    public String getProcess_id() {
        return process_id;
    }

    public void setProcess_id(String process_id) {
        this.process_id = process_id;
    }

    public String getShare_name() {
        return share_name;
    }

    public void setShare_name(String share_name) {
        this.share_name = share_name;
    }

    public String getStart_type() {
        return start_type;
    }

    public void setStart_type(String start_type) {
        this.start_type = start_type;
    }

    public String getService_type() {
        return service_type;
    }

    public void setService_type(String service_type) {
        this.service_type = service_type;
    }

    public String getParam1() {
        return param1;
    }

    public void setParam1(String param1) {
        this.param1 = param1;
    }

    public String getParam2() {
        return param2;
    }

    public void setParam2(String param2) {
        this.param2 = param2;
    }

    public String getParam3() {
        return param3;
    }

    public void setParam3(String param3) {
        this.param3 = param3;
    }

    public String getParam4() {
        return param4;
    }

    public void setParam4(String param4) {
        this.param4 = param4;
    }

    public String getFsrc() {
        return fsrc;
    }

    public void setFsrc(String fsrc) {
        this.fsrc = fsrc;
    }

    public String getCustomer_group() {
        return customer_group;
    }

    public void setCustomer_group(String customer_group) {
        this.customer_group = customer_group;
    }

    public String getLog_channel_name() {
        return log_channel_name;
    }

    public void setLog_channel_name(String log_channel_name) {
        this.log_channel_name = log_channel_name;
    }

    public String getLog_provider_name() {
        return log_provider_name;
    }

    public void setLog_provider_name(String log_provider_name) {
        this.log_provider_name = log_provider_name;
    }

    public String getAttack_tactic() {
        return attack_tactic;
    }

    public void setAttack_tactic(String attack_tactic) {
        this.attack_tactic = attack_tactic;
    }

    public String getAttack_technique() {
        return attack_technique;
    }

    public void setAttack_technique(String attack_technique) {
        this.attack_technique = attack_technique;
    }

    public String getTarget_process_id() {
        return target_process_id;
    }

    public void setTarget_process_id(String target_process_id) {
        this.target_process_id = target_process_id;
    }

    public String getSource_process_id() {
        return source_process_id;
    }

    public void setSource_process_id(String source_process_id) {
        this.source_process_id = source_process_id;
    }

    public String getTarget_thread_id() {
        return target_thread_id;
    }

    public void setTarget_thread_id(String target_thread_id) {
        this.target_thread_id = target_thread_id;
    }

    public String getTarget_user_name() {
        return target_user_name;
    }

    public void setTarget_user_name(String target_user_name) {
        this.target_user_name = target_user_name;
    }

    public String getTarget_domain_name() {
        return target_domain_name;
    }

    public void setTarget_domain_name(String target_domain_name) {
        this.target_domain_name = target_domain_name;
    }

    public String getSource_domain_name() {
        return source_domain_name;
    }

    public void setSource_domain_name(String source_domain_name) {
        this.source_domain_name = source_domain_name;
    }

    public String getStart_function() {
        return start_function;
    }

    public void setStart_function(String start_function) {
        this.start_function = start_function;
    }

    public String getFile_signed() {
        return file_signed;
    }

    public void setFile_signed(String file_signed) {
        this.file_signed = file_signed;
    }

    public String getFile_signature() {
        return file_signature;
    }

    public void setFile_signature(String file_signature) {
        this.file_signature = file_signature;
    }

    public String getWmi_event_type() {
        return wmi_event_type;
    }

    public void setWmi_event_type(String wmi_event_type) {
        this.wmi_event_type = wmi_event_type;
    }

    public String getWmi_operation() {
        return wmi_operation;
    }

    public void setWmi_operation(String wmi_operation) {
        this.wmi_operation = wmi_operation;
    }

    public String getWmi_user() {
        return wmi_user;
    }

    public void setWmi_user(String wmi_user) {
        this.wmi_user = wmi_user;
    }

    public String getWmi_name() {
        return wmi_name;
    }

    public void setWmi_name(String wmi_name) {
        this.wmi_name = wmi_name;
    }

    public String getWmi_type() {
        return wmi_type;
    }

    public void setWmi_type(String wmi_type) {
        this.wmi_type = wmi_type;
    }

    public String getWmi_destination() {
        return wmi_destination;
    }

    public void setWmi_destination(String wmi_destination) {
        this.wmi_destination = wmi_destination;
    }

    public String getWmi_event_namespace() {
        return wmi_event_namespace;
    }

    public void setWmi_event_namespace(String wmi_event_namespace) {
        this.wmi_event_namespace = wmi_event_namespace;
    }

    public String getWmi_query() {
        return wmi_query;
    }

    public void setWmi_query(String wmi_query) {
        this.wmi_query = wmi_query;
    }

    public String getWmi_superchar() {
        return wmi_superchar;
    }

    public void setWmi_superchar(String wmi_superchar) {
        this.wmi_superchar = wmi_superchar;
    }

    public String getWmi_consumer() {
        return wmi_consumer;
    }

    public void setWmi_consumer(String wmi_consumer) {
        this.wmi_consumer = wmi_consumer;
    }

    public String getWmi_filter() {
        return wmi_filter;
    }

    public void setWmi_filter(String wmi_filter) {
        this.wmi_filter = wmi_filter;
    }

    public String getUser_name() {
        return user_name;
    }

    public void setUser_name(String user_name) {
        this.user_name = user_name;
    }

    public String getUser_logon_id() {
        return user_logon_id;
    }

    public void setUser_logon_id(String user_logon_id) {
        this.user_logon_id = user_logon_id;
    }

    public String getUser_logon_guid() {
        return user_logon_guid;
    }

    public void setUser_logon_guid(String user_logon_guid) {
        this.user_logon_guid = user_logon_guid;
    }

    public String getNet_source_host_name() {
        return net_source_host_name;
    }

    public void setNet_source_host_name(String net_source_host_name) {
        this.net_source_host_name = net_source_host_name;
    }

    public String getNet_target_host_name() {
        return net_target_host_name;
    }

    public void setNet_target_host_name(String net_target_host_name) {
        this.net_target_host_name = net_target_host_name;
    }

    public String getNet_source_port_name() {
        return net_source_port_name;
    }

    public void setNet_source_port_name(String net_source_port_name) {
        this.net_source_port_name = net_source_port_name;
    }

    public String getNet_target_port_name() {
        return net_target_port_name;
    }

    public void setNet_target_port_name(String net_target_port_name) {
        this.net_target_port_name = net_target_port_name;
    }

    public String getNet_source_is_ipv6() {
        return net_source_is_ipv6;
    }

    public void setNet_source_is_ipv6(String net_source_is_ipv6) {
        this.net_source_is_ipv6 = net_source_is_ipv6;
    }

    public String getNet_target_is_ipv6() {
        return net_target_is_ipv6;
    }

    public void setNet_target_is_ipv6(String net_target_is_ipv6) {
        this.net_target_is_ipv6 = net_target_is_ipv6;
    }

    public String getReg_target_object() {
        return reg_target_object;
    }

    public void setReg_target_object(String reg_target_object) {
        this.reg_target_object = reg_target_object;
    }

    public String getReg_value_name() {
        return reg_value_name;
    }

    public void setReg_value_name(String reg_value_name) {
        this.reg_value_name = reg_value_name;
    }

    public String getReg_event_type() {
        return reg_event_type;
    }

    public void setReg_event_type(String reg_event_type) {
        this.reg_event_type = reg_event_type;
    }

    public String getReg_old_value_type() {
        return reg_old_value_type;
    }

    public void setReg_old_value_type(String reg_old_value_type) {
        this.reg_old_value_type = reg_old_value_type;
    }

    public String getReg_new_value_type() {
        return reg_new_value_type;
    }

    public void setReg_new_value_type(String reg_new_value_type) {
        this.reg_new_value_type = reg_new_value_type;
    }

    public String getReg_old_value() {
        return reg_old_value;
    }

    public void setReg_old_value(String reg_old_value) {
        this.reg_old_value = reg_old_value;
    }

    public String getReg_new_value() {
        return reg_new_value;
    }

    public void setReg_new_value(String reg_new_value) {
        this.reg_new_value = reg_new_value;
    }

    public String getReg_desired_access() {
        return reg_desired_access;
    }

    public void setReg_desired_access(String reg_desired_access) {
        this.reg_desired_access = reg_desired_access;
    }

    public String getReg_value_data() {
        return reg_value_data;
    }

    public void setReg_value_data(String reg_value_data) {
        this.reg_value_data = reg_value_data;
    }

    public String getReg_value_type() {
        return reg_value_type;
    }

    public void setReg_value_type(String reg_value_type) {
        this.reg_value_type = reg_value_type;
    }

    public String getLogon_process_name() {
        return logon_process_name;
    }

    public void setLogon_process_name(String logon_process_name) {
        this.logon_process_name = logon_process_name;
    }

    public String getTask_name() {
        return task_name;
    }

    public void setTask_name(String task_name) {
        this.task_name = task_name;
    }

    public String getTask_content() {
        return task_content;
    }

    public void setTask_content(String task_content) {
        this.task_content = task_content;
    }

    public String getService_target_name() {
        return service_target_name;
    }

    public void setService_target_name(String service_target_name) {
        this.service_target_name = service_target_name;
    }

    public String getService_source_name() {
        return service_source_name;
    }

    public void setService_source_name(String service_source_name) {
        this.service_source_name = service_source_name;
    }

    public String getService_target_file_path() {
        return service_target_file_path;
    }

    public void setService_target_file_path(String service_target_file_path) {
        this.service_target_file_path = service_target_file_path;
    }

    public String getHash_md5() {
        return hash_md5;
    }

    public void setHash_md5(String hash_md5) {
        this.hash_md5 = hash_md5;
    }

    public String getHash_sha256() {
        return hash_sha256;
    }

    public void setHash_sha256(String hash_sha256) {
        this.hash_sha256 = hash_sha256;
    }

    public String getEvent_log_id() {
        return event_log_id;
    }

    public void setEvent_log_id(String event_log_id) {
        this.event_log_id = event_log_id;
    }

    public String getTarget_process_path() {
        return target_process_path;
    }

    public void setTarget_process_path(String target_process_path) {
        this.target_process_path = target_process_path;
    }

    public String getTarget_process_guid() {
        return target_process_guid;
    }

    public void setTarget_process_guid(String target_process_guid) {
        this.target_process_guid = target_process_guid;
    }

    public String getSource_process_path() {
        return source_process_path;
    }

    public void setSource_process_path(String source_process_path) {
        this.source_process_path = source_process_path;
    }

    public String getSource_process_guid() {
        return source_process_guid;
    }

    public void setSource_process_guid(String source_process_guid) {
        this.source_process_guid = source_process_guid;
    }

    public String getTarget_commandline() {
        return target_commandline;
    }

    public void setTarget_commandline(String target_commandline) {
        this.target_commandline = target_commandline;
    }

    public String getSource_commandline() {
        return source_commandline;
    }

    public void setSource_commandline(String source_commandline) {
        this.source_commandline = source_commandline;
    }

    public String getTarget_current_directory() {
        return target_current_directory;
    }

    public void setTarget_current_directory(String target_current_directory) {
        this.target_current_directory = target_current_directory;
    }

    public String getDesired_access() {
        return desired_access;
    }

    public void setDesired_access(String desired_access) {
        this.desired_access = desired_access;
    }

    public String getFile_status() {
        return file_status;
    }

    public void setFile_status(String file_status) {
        this.file_status = file_status;
    }

    public String getFile_shared_access() {
        return file_shared_access;
    }

    public void setFile_shared_access(String file_shared_access) {
        this.file_shared_access = file_shared_access;
    }

    public String getFile_attributes() {
        return file_attributes;
    }

    public void setFile_attributes(String file_attributes) {
        this.file_attributes = file_attributes;
    }

    public String getFile_description() {
        return file_description;
    }

    public void setFile_description(String file_description) {
        this.file_description = file_description;
    }

    public String getFile_product() {
        return file_product;
    }

    public void setFile_product(String file_product) {
        this.file_product = file_product;
    }

    public String getFile_company() {
        return file_company;
    }

    public void setFile_company(String file_company) {
        this.file_company = file_company;
    }

    public String getFile_hash_md5() {
        return file_hash_md5;
    }

    public void setFile_hash_md5(String file_hash_md5) {
        this.file_hash_md5 = file_hash_md5;
    }

    public String getFile_hash_sha256() {
        return file_hash_sha256;
    }

    public void setFile_hash_sha256(String file_hash_sha256) {
        this.file_hash_sha256 = file_hash_sha256;
    }

    public String getFile_signature_expried() {
        return file_signature_expried;
    }

    public void setFile_signature_expried(String file_signature_expried) {
        this.file_signature_expried = file_signature_expried;
    }

    public String getUser_sid() {
        return user_sid;
    }

    public void setUser_sid(String user_sid) {
        this.user_sid = user_sid;
    }

    public String getUser_target_sid() {
        return user_target_sid;
    }

    public void setUser_target_sid(String user_target_sid) {
        this.user_target_sid = user_target_sid;
    }

    public String getUser_privilege_list() {
        return user_privilege_list;
    }

    public void setUser_privilege_list(String user_privilege_list) {
        this.user_privilege_list = user_privilege_list;
    }

    public String getUser_sam_account_name() {
        return user_sam_account_name;
    }

    public void setUser_sam_account_name(String user_sam_account_name) {
        this.user_sam_account_name = user_sam_account_name;
    }

    public String getUser_display_name() {
        return user_display_name;
    }

    public void setUser_display_name(String user_display_name) {
        this.user_display_name = user_display_name;
    }

    public String getUser_principal_name() {
        return user_principal_name;
    }

    public void setUser_principal_name(String user_principal_name) {
        this.user_principal_name = user_principal_name;
    }

    public String getUser_home_directory() {
        return user_home_directory;
    }

    public void setUser_home_directory(String user_home_directory) {
        this.user_home_directory = user_home_directory;
    }

    public String getUser_home_path() {
        return user_home_path;
    }

    public void setUser_home_path(String user_home_path) {
        this.user_home_path = user_home_path;
    }

    public String getUser_script_path() {
        return user_script_path;
    }

    public void setUser_script_path(String user_script_path) {
        this.user_script_path = user_script_path;
    }

    public String getUser_profile_path() {
        return user_profile_path;
    }

    public void setUser_profile_path(String user_profile_path) {
        this.user_profile_path = user_profile_path;
    }

    public String getUser_work_stations() {
        return user_work_stations;
    }

    public void setUser_work_stations(String user_work_stations) {
        this.user_work_stations = user_work_stations;
    }

    public String getUser_password_last_set() {
        return user_password_last_set;
    }

    public void setUser_password_last_set(String user_password_last_set) {
        this.user_password_last_set = user_password_last_set;
    }

    public String getUser_account_expires() {
        return user_account_expires;
    }

    public void setUser_account_expires(String user_account_expires) {
        this.user_account_expires = user_account_expires;
    }

    public String getUser_primary_group_id() {
        return user_primary_group_id;
    }

    public void setUser_primary_group_id(String user_primary_group_id) {
        this.user_primary_group_id = user_primary_group_id;
    }

    public String getUser_allowed_to_delegate_to() {
        return user_allowed_to_delegate_to;
    }

    public void setUser_allowed_to_delegate_to(String user_allowed_to_delegate_to) {
        this.user_allowed_to_delegate_to = user_allowed_to_delegate_to;
    }

    public String getUser_old_uac_value() {
        return user_old_uac_value;
    }

    public void setUser_old_uac_value(String user_old_uac_value) {
        this.user_old_uac_value = user_old_uac_value;
    }

    public String getUser_new_uac_value() {
        return user_new_uac_value;
    }

    public void setUser_new_uac_value(String user_new_uac_value) {
        this.user_new_uac_value = user_new_uac_value;
    }

    public String getUser_account_control() {
        return user_account_control;
    }

    public void setUser_account_control(String user_account_control) {
        this.user_account_control = user_account_control;
    }

    public String getUser_parameters() {
        return user_parameters;
    }

    public void setUser_parameters(String user_parameters) {
        this.user_parameters = user_parameters;
    }

    public String getUser_sid_history() {
        return user_sid_history;
    }

    public void setUser_sid_history(String user_sid_history) {
        this.user_sid_history = user_sid_history;
    }

    public String getUser_logon_hours() {
        return user_logon_hours;
    }

    public void setUser_logon_hours(String user_logon_hours) {
        this.user_logon_hours = user_logon_hours;
    }

    public String getNet_initiated() {
        return net_initiated;
    }

    public void setNet_initiated(String net_initiated) {
        this.net_initiated = net_initiated;
    }

    public String getNet_flag() {
        return net_flag;
    }

    public void setNet_flag(String net_flag) {
        this.net_flag = net_flag;
    }

    public String getNet_extra_data() {
        return net_extra_data;
    }

    public void setNet_extra_data(String net_extra_data) {
        this.net_extra_data = net_extra_data;
    }

    public String getNet_target_outbound_domain_name() {
        return net_target_outbound_domain_name;
    }

    public void setNet_target_outbound_domain_name(String net_target_outbound_domain_name) {
        this.net_target_outbound_domain_name = net_target_outbound_domain_name;
    }

    public String getNet_target_outbound_user_name() {
        return net_target_outbound_user_name;
    }

    public void setNet_target_outbound_user_name(String net_target_outbound_user_name) {
        this.net_target_outbound_user_name = net_target_outbound_user_name;
    }

    public String getLayer_name() {
        return layer_name;
    }

    public void setLayer_name(String layer_name) {
        this.layer_name = layer_name;
    }

    public String getRemote_user_id() {
        return remote_user_id;
    }

    public void setRemote_user_id(String remote_user_id) {
        this.remote_user_id = remote_user_id;
    }

    public String getRemote_machine_id() {
        return remote_machine_id;
    }

    public void setRemote_machine_id(String remote_machine_id) {
        this.remote_machine_id = remote_machine_id;
    }

    public String getService_old_start_type() {
        return service_old_start_type;
    }

    public void setService_old_start_type(String service_old_start_type) {
        this.service_old_start_type = service_old_start_type;
    }

    public String getService_new_start_type() {
        return service_new_start_type;
    }

    public void setService_new_start_type(String service_new_start_type) {
        this.service_new_start_type = service_new_start_type;
    }

    public String getService_account() {
        return service_account;
    }

    public void setService_account(String service_account) {
        this.service_account = service_account;
    }

    public String getAuthentication_package_name() {
        return authentication_package_name;
    }

    public void setAuthentication_package_name(String authentication_package_name) {
        this.authentication_package_name = authentication_package_name;
    }

    public String getWorkstation_name() {
        return workstation_name;
    }

    public void setWorkstation_name(String workstation_name) {
        this.workstation_name = workstation_name;
    }

    public String getLm_package_name() {
        return lm_package_name;
    }

    public void setLm_package_name(String lm_package_name) {
        this.lm_package_name = lm_package_name;
    }

    public String getRestricted_admin_mode() {
        return restricted_admin_mode;
    }

    public void setRestricted_admin_mode(String restricted_admin_mode) {
        this.restricted_admin_mode = restricted_admin_mode;
    }

    public String getVirtual_account() {
        return virtual_account;
    }

    public void setVirtual_account(String virtual_account) {
        this.virtual_account = virtual_account;
    }

    public String getLogon_failure_reason() {
        return logon_failure_reason;
    }

    public void setLogon_failure_reason(String logon_failure_reason) {
        this.logon_failure_reason = logon_failure_reason;
    }

    public String getContents() {
        return contents;
    }

    public void setContents(String contents) {
        this.contents = contents;
    }

    public String getLogon_status() {
        return logon_status;
    }

    public void setLogon_status(String logon_status) {
        this.logon_status = logon_status;
    }

    public Integer getTime_old_creation() {
        return time_old_creation;
    }

    public void setTime_old_creation(Integer time_old_creation) {
        this.time_old_creation = time_old_creation;
    }

    public Integer getTime_new_creation() {
        return time_new_creation;
    }

    public void setTime_new_creation(Integer time_new_creation) {
        this.time_new_creation = time_new_creation;
    }

    public Integer getBuffer_leng() {
        return buffer_leng;
    }

    public void setBuffer_leng(Integer buffer_leng) {
        this.buffer_leng = buffer_leng;
    }

    public Integer getNet_inbound_count() {
        return net_inbound_count;
    }

    public void setNet_inbound_count(Integer net_inbound_count) {
        this.net_inbound_count = net_inbound_count;
    }

    public Integer getNet_outbound_count() {
        return net_outbound_count;
    }

    public void setNet_outbound_count(Integer net_outbound_count) {
        this.net_outbound_count = net_outbound_count;
    }

    public Long getReg_value_data_leng() {
        return reg_value_data_leng;
    }

    public void setReg_value_data_leng(Long reg_value_data_leng) {
        this.reg_value_data_leng = reg_value_data_leng;
    }

    public Integer getKey_length() {
        return key_length;
    }

    public void setKey_length(Integer key_length) {
        this.key_length = key_length;
    }

    public String getLogon_substatus() {
        return logon_substatus;
    }

    public void setLogon_substatus(String logon_substatus) {
        this.logon_substatus = logon_substatus;
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    public String getCommand_data() {
        return command_data;
    }

    public void setCommand_data(String command_data) {
        this.command_data = command_data;
    }

    public Integer getThreats() {
        return threats;
    }

    public void setThreats(Integer threats) {
        this.threats = threats;
    }

    public String getAlert_type() {
        return alert_type;
    }

    public void setAlert_type(String alert_type) {
        this.alert_type = alert_type;
    }

    public String getRelative_target_name() {
        return relative_target_name;
    }

    public void setRelative_target_name(String relative_target_name) {
        this.relative_target_name = relative_target_name;
    }

    public String getSubtype() {
        return subtype;
    }

    public void setSubtype(String subtype) {
        this.subtype = subtype;
    }

    public String getResource_attributes() {
        return resource_attributes;
    }

    public void setResource_attributes(String resource_attributes) {
        this.resource_attributes = resource_attributes;
    }

    public String getSrc_mac() {
        return src_mac;
    }

    public void setSrc_mac(String src_mac) {
        this.src_mac = src_mac;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public Long getUptime() {
        return uptime;
    }

    public void setUptime(Long uptime) {
        this.uptime = uptime;
    }

    public String getFull_request() {
        return full_request;
    }

    public void setFull_request(String full_request) {
        this.full_request = full_request;
    }

    public String getSignature_raw() {
        return signature_raw;
    }

    public void setSignature_raw(String signature_raw) {
        this.signature_raw = signature_raw;
    }

    public String getUser_agent() {
        return user_agent;
    }

    public void setUser_agent(String user_agent) {
        this.user_agent = user_agent;
    }

    public String getTenant() {
        return tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public String getAdministrator() {
        return administrator;
    }

    public void setAdministrator(String administrator) {
        this.administrator = administrator;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public String getMachine() {
        return machine;
    }

    public void setMachine(String machine) {
        this.machine = machine;
    }

    public String getObjecttype() {
        return objecttype;
    }

    public void setObjecttype(String objecttype) {
        this.objecttype = objecttype;
    }

    public String getFieldschanges() {
        return fieldschanges;
    }

    public void setFieldschanges(String fieldschanges) {
        this.fieldschanges = fieldschanges;
    }

    public String getFunction_name() {
        return function_name;
    }

    public void setFunction_name(String function_name) {
        this.function_name = function_name;
    }

    public String getTime_generated() {
        return time_generated;
    }

    public void setTime_generated(String time_generated) {
        this.time_generated = time_generated;
    }

    public Long getLocal_timestamp() {
        return local_timestamp;
    }

    public void setLocal_timestamp(Long local_timestamp) {
        this.local_timestamp = local_timestamp;
    }

    public String getVolumes() {
        return volumes;
    }

    public void setVolumes(String volumes) {
        this.volumes = volumes;
    }

    public String getObject_type() {
        return object_type;
    }

    public void setObject_type(String object_type) {
        this.object_type = object_type;
    }

    public String getOld_value() {
        return old_value;
    }

    public void setOld_value(String old_value) {
        this.old_value = old_value;
    }

    public String getNew_value() {
        return new_value;
    }

    public void setNew_value(String new_value) {
        this.new_value = new_value;
    }

    public String getObject_value_name() {
        return object_value_name;
    }

    public void setObject_value_name(String object_value_name) {
        this.object_value_name = object_value_name;
    }

    public String getHost_application() {
        return host_application;
    }

    public void setHost_application(String host_application) {
        this.host_application = host_application;
    }

    public String getHost_name() {
        return host_name;
    }

    public void setHost_name(String host_name) {
        this.host_name = host_name;
    }

    public String getScript_name() {
        return script_name;
    }

    public void setScript_name(String script_name) {
        this.script_name = script_name;
    }

    public String getLog_name() {
        return log_name;
    }

    public void setLog_name(String log_name) {
        this.log_name = log_name;
    }

    public String getGroup_name() {
        return group_name;
    }

    public void setGroup_name(String group_name) {
        this.group_name = group_name;
    }

    public String getAgent_id() {
        return agent_id;
    }

    public void setAgent_id(String agent_id) {
        this.agent_id = agent_id;
    }

    public String getRule() {
        return rule;
    }

    public void setRule(String rule) {
        this.rule = rule;
    }

    public String getTarget_hostname() {
        return target_hostname;
    }

    public void setTarget_hostname(String target_hostname) {
        this.target_hostname = target_hostname;
    }

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }

    public String getGroup_domain() {
        return group_domain;
    }

    public void setGroup_domain(String group_domain) {
        this.group_domain = group_domain;
    }

    public String getArn() {
        return arn;
    }

    public void setArn(String arn) {
        this.arn = arn;
    }

    public String getSession_issuer_type() {
        return session_issuer_type;
    }

    public void setSession_issuer_type(String session_issuer_type) {
        this.session_issuer_type = session_issuer_type;
    }

    public String getEvent_source() {
        return event_source;
    }

    public void setEvent_source(String event_source) {
        this.event_source = event_source;
    }

    public String getEvent_name() {
        return event_name;
    }

    public void setEvent_name(String event_name) {
        this.event_name = event_name;
    }

    public String getRequest_attribute() {
        return request_attribute;
    }

    public void setRequest_attribute(String request_attribute) {
        this.request_attribute = request_attribute;
    }

    public String getRequest_container_command() {
        return request_container_command;
    }

    public void setRequest_container_command(String request_container_command) {
        this.request_container_command = request_container_command;
    }

    public String getResponse_access_key_user_name() {
        return response_access_key_user_name;
    }

    public void setResponse_access_key_user_name(String response_access_key_user_name) {
        this.response_access_key_user_name = response_access_key_user_name;
    }

    public String getResponse_user_password() {
        return response_user_password;
    }

    public void setResponse_user_password(String response_user_password) {
        this.response_user_password = response_user_password;
    }

    public String getResponse_puiblic_accessible() {
        return response_puiblic_accessible;
    }

    public void setResponse_puiblic_accessible(String response_puiblic_accessible) {
        this.response_puiblic_accessible = response_puiblic_accessible;
    }

    public String getEvent_type() {
        return event_type;
    }

    public void setEvent_type(String event_type) {
        this.event_type = event_type;
    }

    public String getSignature_id() {
        return signature_id;
    }

    public void setSignature_id(String signature_id) {
        this.signature_id = signature_id;
    }

    public Map<String, String> getUnknownFields() {
        return unknownFields;
    }

    public void setUnknownFields(String key, String value) {
        this.unknownFields.put(key, value);
    }

    public void setUnknownFields(Map<String, String> unknownFields) {
        this.unknownFields = unknownFields;
    }

    public String getScript_content() {
        return script_content;
    }

    public void setScript_content(String script_content) {
        this.script_content = script_content;
    }

    public String getOrganization_group() {
        return organization_group;
    }

    public void setOrganization_group(String organization_group) {
        this.organization_group = organization_group;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getPowershell_scriptblock_text() {
        return powershell_scriptblock_text;
    }

    public void setPowershell_scriptblock_text(String powershell_scriptblock_text) {
        this.powershell_scriptblock_text = powershell_scriptblock_text;
    }

    public String getDevice_product() {
        return device_product;
    }

    public void setDevice_product(String device_product) {
        this.device_product = device_product;
    }

    public String getObject() {
        return object;
    }

    public void setObject(String object) {
        this.object = object;
    }

    public String getFile_originalname() {
        return file_originalname;
    }

    public void setFile_originalname(String file_originalname) {
        this.file_originalname = file_originalname;
    }

    public String getParent_file_product() {
        return parent_file_product;
    }

    public void setParent_file_product(String parent_file_product) {
        this.parent_file_product = parent_file_product;
    }

    

    
}
