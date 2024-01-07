import os
import traceback

from typing import List,Optional,Union
from sqlalchemy import Column, Enum, func
import telephant_server
import telephant_server.asn
import telephant_server.auth
import datetime

from fastapi import FastAPI,Request, status
from fastapi.exceptions import HTTPException
from fastapi.templating import Jinja2Templates
import webcrud
from pydantic import BaseModel
from typing import List,Tuple,Type,Optional,Callable

import re

from pydantic import field_serializer
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select
import datetime
import enum
import ipaddress


from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# h = pwd_context.hash(user_data.password)
# pwd_context.verify(input_password, hash)

class IPRole(enum.IntEnum):
    UNKNOWN = 0
    SRC = 1
    DST = 2
    TRACEROUTE_HOP = 3
    ICMP_SRC = 4

class ReportIP(SQLModel, table=True):
    reportip_id: Optional[int] =Field(default=None, primary_key=True)
    ip_id: Optional[int] =Field(default=None, foreign_key="ipaddress.ip_id")
    report_id: Optional[int] =Field(default=None, foreign_key="report.report_id")
    role: IPRole =Field(sa_column=Column(Enum(IPRole)))

class IPAddress(SQLModel, table=True):
    ip_id: Optional[int] =Field(default=None, primary_key=True)
    afi: int =Field(index=True)
    a0: int =Field(index=True)
    a1: Optional[int] =Field(nullable=True, index=True)
    a2: Optional[int] =Field(nullable=True, index=True)
    a3: Optional[int] =Field(nullable=True, index=True)
    asns: Optional[List["IPAddressASN"]] =Relationship(back_populates="ip")
    reports: Optional[List["Report"]] =Relationship(back_populates="ips", link_model=ReportIP)

class IPAddressASN(SQLModel, table=True):
    ipasn_id: Optional[int] = Field(default=None, primary_key=True)
    ip_id: Optional[int] =Field(default=None, foreign_key="ipaddress.ip_id")
    asn: int =Field(index=True)
    created_ts: datetime.datetime =Field(default_factory=datetime.datetime.utcnow, nullable=False)
    ip: Optional[IPAddress] =Relationship(back_populates="asns")

class UserGroup(SQLModel, table=True):
    user_id: Optional[int] =Field(default=None, foreign_key="user.user_id", primary_key=True)
    group_id: Optional[int] =Field(default=None, foreign_key="group.group_id", primary_key=True)

class User(SQLModel, table=True):
    user_id: Optional[int] = Field(default=None, primary_key=True)
    email: str
    fullname: str
    password_hash: Optional[str] =None
    enabled: bool
    created_ts: datetime.datetime =Field(default_factory=datetime.datetime.utcnow, nullable=False)
    lastlogin_ts: Optional[datetime.datetime] =Field(nullable=True)
    groups: Optional[List["Group"]] =Relationship(back_populates="users", link_model=UserGroup) #relationship("Group", secondary=user_group, back_populates="users")
    api_keys: Optional[List["ApiKey"]] =Relationship(back_populates="user")  #relationship("ApiKey", backref=backref("users"))
    reports: Optional[List["Report"]] =Relationship(back_populates="reporter")

class Group(SQLModel, table=True):
    group_id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_ts: datetime.datetime =Field(default_factory=datetime.datetime.utcnow, nullable=False)
    users: Optional[List[User]] = Relationship(back_populates="groups", link_model=UserGroup) #relationship("User", secondary=user_group, back_populates="groups")

class ApiKey(SQLModel, table=True):
    apikey_id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.user_id")
    key: str
    created_ts: datetime.datetime =Field(default_factory=datetime.datetime.utcnow, nullable=False)
    user: User =Relationship(back_populates="api_keys")

class Report(SQLModel, table=True):
    report_id: Optional[int] =Field(default=None, primary_key=True)
    filename: Optional[str] =Field(nullable=True)
    created_ts: datetime.datetime =Field(default_factory=datetime.datetime.utcnow, nullable=False)
    lastview_ts: Optional[datetime.datetime] =Field(nullable=True)
    reporter_id: Optional[int] =Field(default=None, foreign_key="user.user_id")
    group_id: Optional[int] =Field(default=None, foreign_key="group.group_id")
    reporter: User =Relationship(back_populates="reports")
    ips: Optional[List[IPAddress]] =Relationship(back_populates="reports", link_model=ReportIP)





engine = create_engine(telephant_server.config['db_sqlite'])
SQLModel.metadata.create_all(engine)

### sqlite3-specific CIRD implementation
def create_ip4(ip: ipaddress.IPv4Address) -> int:
    with Session(engine) as session:
        a = IPAddress(afi=4, a0=int(ip))
        session.add(a)
        session.commit()
        session.refresh(a)

        for asn in telephant_server.asn.lookup_asns(ip):
            ipasn = IPAddressASN(ip_id=a.ip_id, asn=asn)
            session.add(ipasn)
        session.commit()
        session.refresh(a)
        
        return a


def create_ip6(ip: ipaddress.IPv6Address) -> int:
    iip = int(ip)
    a3 = iip & 0xFFFFFFFF
    a2 = (iip >> 32) & 0xFFFFFFFF
    a1 = (iip >> 64) & 0xFFFFFFFF
    a0 = (iip >> 96) & 0xFFFFFFFF

    with Session(engine) as session:
        a = IPAddress(afi=6, a0=a0, a1=a1, a2=a2, a3=a3)
        session.add(a)
        session.commit()
        session.refresh(a)

        for asn in telephant_server.asn.lookup_asns(ip):
            ipasn = IPAddressASN(ip_id=a.ip_id, asn=asn)
            session.add(ipasn)
        session.commit()
        session.refresh(a)
        
        return a


def add_ip4_statement(statement, ipn: ipaddress.IPv4Network):
    return statement.where(IPAddress.afi == 4, (IPAddress.a0.op('&')(int(ipn.netmask)) == int(ipn.network_address)))


def select_ip4(ipn: ipaddress.IPv4Network) -> List[IPAddress]:
    with Session(engine) as session:
        statement = select(IPAddress)
        return session.exec(add_ip4_statement(statement, ipn)).all()


def add_ip6_statement(statement, ipn: ipaddress.IPv6Network):
    iipn = int(ipn.network_address)
    a3 = iipn & 0xFFFFFFFF
    a2 = (iipn >> 32) & 0xFFFFFFFF
    a1 = (iipn >> 64) & 0xFFFFFFFF
    a0 = (iipn >> 96) & 0xFFFFFFFF

    mipn = int(ipn.netmask)
    m3 = mipn & 0xFFFFFFFF
    m2 = (mipn >> 32) & 0xFFFFFFFF
    m1 = (mipn >> 64) & 0xFFFFFFFF
    m0 = (mipn >> 96) & 0xFFFFFFFF

    return statement.where(IPAddress.afi == 6, (IPAddress.a0.op('&')(m0) == a0), (IPAddress.a1.op('&')(m1) == a1), (IPAddress.a2.op('&')(m2) == a2), (IPAddress.a3.op('&')(m3) == a3))

def select_ip6(ipn: ipaddress.IPv6Network) -> List[IPAddress]:
    with Session(engine) as session:
        statement = select(IPAddress)
        return session.exec(add_ip6_statement(statement, ipn)).all()

    
def decode_db_ip(dbip: IPAddress) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if dbip.afi == 4:
        return ipaddress.IPv4Address(dbip.a0)
    elif dbip.afi == 6:
        a = (dbip.a0 << 96) | (dbip.a1 << 64) | (dbip.a2 << 32) | dbip.a3
        return ipaddress.IPv6Address(a)
    else:
        raise ValueError(f"Unsupported AFI in IPAddress record: {str(dbip)}")


def verify_apikey_get_user(apikey: str) -> Optional[User]:
    """ Returns User object for the key or None if no User for the key was found
    """
    with Session(engine) as session:
        return session.exec(select(User).join(ApiKey).where(ApiKey.key == apikey)).first()


def login_user_google(user_data) -> User:
    eml = user_data.get('email')
    if eml:
        with Session(engine) as session:
            fn = user_data.get('name', '')
            u = session.exec(select(User).where(User.email == eml)).first()
            if u:
                u.lastlogin_ts = datetime.datetime.utcnow()
                session.commit()
            else:
                u = User(email=eml, fullname=fn, created_ts=datetime.datetime.utcnow(), enabled=True, lastlogin_ts=datetime.datetime.utcnow())
                session.add(u)
                session.commit()
                session.refresh(u)

            return u
    else:
        raise ValueError("Can not find email in user_data.")

def login_user_password(eml, password):
    with Session(engine) as session:
        u = session.exec(select(User).where(User.email == eml)).first()
        if u and pwd_context.verify(password, u.password_hash):
            u.lastlogin_ts = datetime.datetime.utcnow()
            session.commit()
            session.refresh(u)
            return u
        else:
            if eml in telephant_server.config.get('admins', {}) and password == telephant_server.config['admins'][eml]:
                u = User(email=eml, fullname='Initialized', created_ts=datetime.datetime.utcnow(), enabled=True, lastlogin_ts=datetime.datetime.utcnow())
                session.add(u)
                session.commit()
                session.refresh(u)
                return u
            else:
                return None


def new_report(rdir: str, user: User, ts: datetime.datetime) -> Tuple[int, str]:
    """ Return (report_id, report_path_filename)
    """
    with Session(engine) as session:        
        r = Report(created_ts=ts, reporter_id=user.user_id)
        session.add(r)
        session.commit()
        session.refresh(r)
        rfn = os.path.join(rdir, f"{r.report_id}.yaml")
        r.filename = rfn
        session.commit()
        return (r.report_id, rfn)


def filter_index_ip(ip: ipaddress.IPv6Address | ipaddress.IPv4Address):
    if telephant_server.config.get('index_ip_filter', 'all') == 'public' and not ip.is_global:
        return False
    else:
        return True

def index_ip(rid: int, ip: ipaddress.IPv6Address | ipaddress.IPv4Address, role: IPRole):
    if not filter_index_ip(ip):
        return

    if ip.version == 6:
        ipn = ipaddress.IPv6Network(ip)
        db_ips = list(select_ip6(ipn))
        if not db_ips:
            db_ips = [create_ip6(ip),]
    elif ip.version == 4:
        ipn = ipaddress.IPv4Network(ip)
        db_ips = list(select_ip4(ipn))
        if not db_ips:
            db_ips = [create_ip4(ip),]

    with Session(engine) as session:
        if not list(session.exec(select(ReportIP).where(ReportIP.report_id == rid, ReportIP.ip_id == db_ips[0].ip_id, ReportIP.role == role)).all()):
            rip = ReportIP(report_id=rid, ip_id=db_ips[0].ip_id, role=role)
            session.add(rip)
            session.commit()


def index_report(rid, report):

    # TODO: test that report group is allowed for the user and record report-group
    gid = report.get("group", None)
    if gid:
        with Session(engine) as session:
            r = session.exec(select(Report).where(Report.report_id == rid)).one()
            g = session.exec(select(Group).join(UserGroup).where(UserGroup.user_id == r.report_id).where(Group.group_id == gid)).first()
            if g:
                r.group_id = g.group_id
                session.commit()
            else:
                print(f"Warn: Invalid group reported in report {rid}")

    for ip in report.get('host_ip_address', []):
        index_ip(rid, ipaddress.ip_address(ip), IPRole.SRC)
    for t in report.get('targets', []):
        if 'ipaddress' in t:
            index_ip(rid, ipaddress.ip_address(t['ipaddress']), IPRole.DST)
    for ip in report.get('traceroute_seen_hops', []):
        index_ip(rid, ipaddress.ip_address(ip), IPRole.TRACEROUTE_HOP)


def get_report(rid: int) -> Report:
    with Session(engine) as session:
        r = session.exec(select(Report).where(Report.report_id == rid)).first()
        if r:
            r.lastview_ts = datetime.datetime.utcnow()
            session.commit()
            session.refresh(r)
        return r


class ReportMeta(BaseModel):
    report_id: int
    reporter: str
    created_ts: datetime.datetime
    sips: List[str]
    dips: List[str]
    asns: List[int]

class ReportsCRUD(webcrud.WebCRUD):
    FORMATTING_HINTS={'report_id':{'href':'/report?showreport=', 'column_name': 'Report ID'},
                      'reporter': {'column_name': 'Reporter'},
                      'created_ts': {'column_name': 'Created'},
                      'sips':{'column_name': 'Source IPs'},
                      'dips':{'column_name': 'Destination IPs'},
                      '__page__': {'search_enabled': True, }
                      }
    
    asnmatch = re.compile(r'^\s*AS([0-9]+)\s*$')

    def __init__(self, app: FastAPI, template_engine: Jinja2Templates, urlprefix: str =''):
        super().__init__(app, template_engine, ReportMeta, 'Reports', readonly=True, urlprefix=urlprefix, formatting_hints=self.FORMATTING_HINTS)

    def db2web(self, dbreport: Report) -> ReportMeta:
        with Session(engine) as session:
            sips = session.exec(select(IPAddress).join(ReportIP).join(Report).where(Report.report_id == dbreport.report_id).where(ReportIP.role == IPRole.SRC)).all()
            dips = session.exec(select(IPAddress).join(ReportIP).join(Report).where(Report.report_id == dbreport.report_id).where(ReportIP.role == IPRole.DST)).all()

        asns = set()
        for ip in dbreport.ips:
            for asnobj in ip.asns:
                asns.add(asnobj.asn)

        return ReportMeta(report_id=dbreport.report_id,
                          reporter=dbreport.reporter.email,
                          created_ts=dbreport.created_ts,
                          sips=list([str(decode_db_ip(ip)) for ip in sips]),
                          dips=list([str(decode_db_ip(ip)) for ip in dips]),
                          asns=list(asns))


    def _search_statement(self, _:Optional[str], search: Optional[str] =None, statement=select(Report)):
        if search:
            try:
                searchnet = ipaddress.ip_network(search)
                statement = statement.distinct(Report.report_id).join(ReportIP).join(IPAddress)
                if searchnet.version == 6:
                    return add_ip6_statement(statement, searchnet)
                elif searchnet.version == 4:
                    return add_ip4_statement(statement, searchnet)
            except:
                pass
                #print(traceback.format_exc())
            try:
                m = self.asnmatch.match(search.strip())
                if m:
                    asn = int(m.group(1))
                    return statement.distinct(Report.report_id).join(ReportIP).join(IPAddressASN).where(IPAddressASN.asn == asn)
            except:
                pass
                
            try:
                rid = int(search.strip())
                return statement.where(Report.report_id == rid)
            except:
                pass
        
        return statement
    
    def search(self, request: Request, offset: int, count: int, search: Optional[str] =None) -> Tuple[List[Tuple[int,ReportMeta]],int]:
        usereml = telephant_server.auth.get_user_email(request)
        with Session(engine) as session:
            total = session.exec(self._search_statement(usereml, search, select(func.count(Report.report_id)))).one()
            result = [(dbreport.report_id, self.db2web(dbreport)) for dbreport in session.exec(self._search_statement(search).offset(offset).limit(count)).all()]
            return (result, total)
        
    def get(self, _: Request, id: int) -> ReportMeta:
        with Session(engine) as session:
            dbreport = session.exec(select(Report).where(Report.report_id == id)).first()
            return self.db2web(dbreport)

    def generate_crud_endpoints(self):
        self.generate_backend_crud_endpoints(self.search, self.get)


class MyReportsCRUD(ReportsCRUD):
    def _search_statement(self, usereml: Optional[str], search: Optional[str] =None, statement=select(Report)):
        if search:
            try:
                searchnet = ipaddress.ip_network(search)
                statement = statement.distinct(Report.report_id).join(ReportIP).join(IPAddress)
                if searchnet.version == 6:
                    return add_ip6_statement(statement, searchnet)
                elif searchnet.version == 4:
                    return add_ip4_statement(statement, searchnet)
            except:
                pass
                #print(traceback.format_exc())
            try:
                m = self.asnmatch.match(search.strip())
                if m:
                    asn = int(m.group(1))
                    return statement.distinct(Report.report_id).join(ReportIP).join(IPAddressASN).where(IPAddressASN.asn == asn)
            except:
                pass
                
            try:
                rid = int(search.strip())
                return statement.where(Report.report_id == rid)
            except:
                pass
        
        return statement.join(User).where(User.email == usereml)



#class Test1(BaseModel):
#    test1: str
#
#class Test2(BaseModel):
#    test2: int

class GroupIO(BaseModel):
    group_id: Optional[int] =None
    name: str
    created_ts: Optional[datetime.datetime] =None
    users: List[str]
    #test_select: IPRole
    #test: Union[Test1,Test2]

    @field_serializer('created_ts')
    def serialize_datetime(self, t: datetime, _info):
        return t.isoformat('T','minutes')

class GroupsCRUD(webcrud.WebCRUD):
    FORMATTING_HINTS={'group_id': {'column_name': 'Group ID', 'show_in_edit': False, 'readonly': True},
                      'created_ts': {'column_name': 'Created', 'show_in_edit': False, 'readonly': True},
                      'name': {'column_name': 'Group name'},
                      'users': {'column_name': 'Users (e-mails)'},
                      #'test': {'selector': 'test_select', 'selector_map': {'UNKNOWN': 'Test1', 'SRC': 'Test2'}},
                      #'test_select': {'default_value_js': '"UNKNOWN"'},
                      '__page__': { 'search_enabled': True }
                      }

    def __init__(self, app: FastAPI, template_engine: Jinja2Templates, urlprefix: str =''):
        super().__init__(app, template_engine, GroupIO, 'Groups', readonly=False, urlprefix=urlprefix, formatting_hints=self.FORMATTING_HINTS)

    def db2web(self, dbgroup: Group) -> GroupIO:
        return GroupIO(**dbgroup.model_dump(), users=[u.email for u in dbgroup.users])

    def generate_crud_endpoints(self):

        def _search_statement(usereml: str, search: Optional[str] =None, statement=select(Group)):
            statement = statement.join(UserGroup).join(User).where(User.email == usereml)
            if search:
                return statement.distinct(Group.group_id).where(Group.name == search.strip())
            
            return statement

        def search(request: Request, offset: int, count: int, search: Optional[str] =None) -> Tuple[List[Tuple[int,self.cls]],int]:
            usereml = telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                total = session.exec(_search_statement(usereml, search, select(func.count(Group.group_id)))).one()
                result = [(dbgroup.group_id, self.db2web(dbgroup)) for dbgroup in session.exec(_search_statement(usereml, search).offset(offset).limit(count)).all()]
                return (result, total)
        
        def get(request: Request, id: int) -> self.cls:
            usereml = telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                dbgroup = session.exec(select(Group).join(UserGroup).join(User).where(Group.group_id == id).where(User.email == usereml)).first()
                if not dbgroup:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Object not found",
                    )
                return self.db2web(dbgroup)

        def create(request: Request, element: self.cls):
            usereml = telephant_server.auth.require_user_email(request)
            o = Group(name=element.name, users=[])
            with Session(engine) as session:
                for un in list(set(element.users)|{usereml}):
                    for u in session.exec(select(User).where(User.email == un)).all():
                        o.users.append(u)
                session.add(o)
                session.commit()
                session.refresh(o)
            return o.group_id

        def update(request: Request, id: int, element: self.cls):
            usereml = telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                try:
                    o = session.exec(select(Group).join(UserGroup).join(User).where(Group.group_id == id).where(User.email == usereml)).one()
                except:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Object not found",
                    )
                o.users = []
                o.name = element.name
                for un in element.users:
                    for u in session.exec(select(User).where(User.email == un)).all():
                        o.users.append(u)
                session.commit()

        def delete(request: Request, id: int):
            usereml = telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                try:
                    o = session.exec(select(Group).join(UserGroup).join(User).where(Group.group_id == id).where(User.email == usereml)).one()
                except:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Object not found",
                    )
                session.delete(o)
                session.commit()

        self.generate_backend_crud_endpoints(search, get, create, update, delete)


class ApiKeyIO(BaseModel):
    apikey_id: Optional[int] =None
    key: Optional[str] =None
    created_ts: Optional[datetime.datetime] =None
    @field_serializer('created_ts')
    def serialize_datetime(self, t: datetime, _info):
        return t.isoformat('T','minutes')

class APIKeysCRUD(webcrud.WebCRUD):
    FORMATTING_HINTS={'apikey_id': {'column_name': 'API Key ID', 'show_in_edit': False, 'readonly': True},
                      'created_ts': {'column_name': 'Created', 'show_in_edit': False, 'readonly': True},
                      'key': {'column_name': 'Key', 'readonly': True},
                      '__page__': {'edit_header': 'Key will be auto-generated on first save. No further changes are allowed, except deletion of the key.'}
                      }

    def __init__(self, app: FastAPI, template_engine: Jinja2Templates, urlprefix: str =''):
        super().__init__(app, template_engine, ApiKeyIO, 'APIKeys', readonly=False, urlprefix=urlprefix, formatting_hints=self.FORMATTING_HINTS)

    def db2web(self, dbak: ApiKey) -> ApiKeyIO:
        return ApiKeyIO(**dbak.model_dump())

    def generate_crud_endpoints(self):

        def _search_statement(usereml: str, search: Optional[str] =None, statement=select(ApiKey)):
            return statement.distinct(ApiKey.apikey_id).join(User).where(User.email == usereml)

        def search(request: Request, offset: int, count: int, search: Optional[str] =None) -> Tuple[List[Tuple[int,self.cls]],int]:
            usereml = telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                total = session.exec(_search_statement(usereml, search, select(func.count(ApiKey.apikey_id)))).one()
                result = [(dbak.apikey_id, self.db2web(dbak)) for dbak in session.exec(_search_statement(usereml, search).offset(offset).limit(count)).all()]
                return (result, total)
        
        def get(request: Request, id: int) -> self.cls:
            usereml = telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                try:
                    dbak = session.exec(select(ApiKey).where(ApiKey.apikey_id == id)).where(ApiKey.user.email == usereml).one()
                except:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Object not found",
                    )
                return self.db2web(dbak)

        def create(request: Request, element: self.cls):
            # we just ignore input and generate new random key
            usereml = telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                while True:
                    k = telephant_server.auth.gen_api_key()
                    if not session.exec(select(ApiKey).where(ApiKey.key == k)).first():
                        break
                    
                u = session.exec(select(User).where(User.email == usereml)).one()
                o = ApiKey(user=u, key=k)
                session.add(o)
                session.commit()
                session.refresh(o)
            return o.apikey_id

        def update(request: Request, id: int, element: self.cls):
            raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="No updates of API keys are allowed",
                    )

        def delete(request: Request, id: int):
            usereml = telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                try:
                    o = session.exec(select(ApiKey).where(ApiKey.group_id == id).where(User.email == usereml)).one()
                except:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Object not found",
                    )
                session.delete(o)
                session.commit()

        self.generate_backend_crud_endpoints(search, get, create, update, delete)


class UserIO(BaseModel):
    user_id: Optional[int] =None
    email: str
    fullname: str
    enabled: bool
    password: Optional[str] =None
    created_ts: Optional[datetime.datetime] =None
    lastlogin_ts: Optional[datetime.datetime] =None
    groups: Optional[List[str]]

    @field_serializer('created_ts', 'lastlogin_ts')
    def serialize_datetime(self, t: datetime, _info):
        if t:
            return t.isoformat('T','minutes')

class UsersCRUD(webcrud.WebCRUD):
    FORMATTING_HINTS={'user_id':{'column_name': 'User ID', 'show_in_edit': False},
                      'email':{'column_name': 'E-Mail'},
                      'fullname':{'column_name': 'E-Mail'},
                      'enabled':{'column_name': 'Enabled'},
                      'password':{'column_name': 'Password', 'show_in_table': False},
                      'created_ts':{'column_name': 'Created', 'show_in_edit': False},
                      'lastlogin_ts':{'column_name': 'Last Login', 'show_in_edit': False},
                      '__page__': { 'search_enabled': True }
                      }

    def __init__(self, app: FastAPI, template_engine: Jinja2Templates, urlprefix: str =''):
        super().__init__(app, template_engine, UserIO, 'Users', readonly=False, urlprefix=urlprefix, formatting_hints=self.FORMATTING_HINTS)

    def db2web(self, dbuser: User) -> UserIO:
        #return UserIO(user_id=dbuser.user_id, email=dbuser.email, fullname=dbuser.fullname, enabled=dbuser.enabled, password="",
        #              created_ts=dbuser.created_ts, lastlogin_ts=dbuser.lastlogin_ts, groups=[g.name for g in dbuser.groups])
        return UserIO(**dbuser.model_dump(), groups=[g.name for g in dbuser.groups])
    
    def generate_crud_endpoints(self):

        def _search_statement(usereml: str, search: Optional[str] =None, statement=select(User)):
            if search:
                return statement.distinct(User.user_id).where(User.email == search.strip())
            
            return statement

        def search(request: Request, offset: int, count: int, search: Optional[str] =None) -> Tuple[List[Tuple[int,self.cls]],int]:
            usereml = telephant_server.auth.require_admin_email(request)

            with Session(engine) as session:
                total = session.exec(_search_statement(usereml, search, select(func.count(User.user_id)))).one()
                result = [(dbuser.user_id, self.db2web(dbuser)) for dbuser in session.exec(_search_statement(usereml, search).offset(offset).limit(count)).all()]
                return (result, total)
        
        def get(request: Request, id: int) -> self.cls:
            telephant_server.auth.require_admin_email(request)
            with Session(engine) as session:
                dbuser = session.exec(select(User).where(User.user_id == id)).one()
                return self.db2web(dbuser)

        def create(request: Request, element: self.cls):
            telephant_server.auth.require_admin_email(request)
            o = User(fullname=element.fullname, email=element.email, enabled=element.enabled)
            if element.password:
                o.password_hash = pwd_context.hash(element.password)

            with Session(engine) as session:
                session.add(o)
                session.commit()
                session.refresh(o)
            return o.user_id

        def update(request: Request, id: int, element: self.cls):
            telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                try:
                    o = session.exec(select(User).where(User.user_id == id)).one()
                except:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Object not found",
                    )
                o.email = element.email
                o.fullname = element.fullname
                o.enabled = element.enabled
                if element.password:
                    o.password_hash = pwd_context.hash(element.password)
                session.commit()

        def delete(request: Request, id: int):
            telephant_server.auth.require_user_email(request)
            with Session(engine) as session:
                try:
                    o = session.exec(select(User).where(User.user_id == id)).one()
                except:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Object not found",
                    )
                for ak in o.api_keys:
                    session.delete(ak)

                for r in o.reports:
                    try:
                        os.unlink(r.filename)
                    except Exception as e:
                        print(e)
                    session.delete(r)
                
                for ug in session.exec(select(UserGroup).where(UserGroup.user_id)).all():
                    session.delete(ug)

                session.delete(o)
                session.commit()

        self.generate_backend_crud_endpoints(search, get, create, update, delete)

