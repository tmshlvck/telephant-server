#!/usr/bin/env python3
#
# Telephant-server
# Copyright (C) 2023 Tomas Hlavacek (tmshlvck@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__version__ = '0.1.0'

import os
import logging
import yaml

def load_appconfig(config_file: str):
    with open(config_file, 'r') as fd:
        c = yaml.load(fd, Loader=yaml.SafeLoader)
    return c

app_config_file = os.environ.get("TELEPHANT_SERVER_CONFIG", '/telephant/server-config.yaml')
config = load_appconfig(app_config_file)

logcfg = {'format': '%(asctime)s %(levelname)s %(message)s'}
if config.get('debug', False):
    logcfg['level'] = logging.DEBUG
else:
    logcfg['level'] = logging.WARN

if config.get('logfile', None):
    logcfg['filename'] = config['logfile']
logging.basicConfig(**logcfg)


from typing import Annotated,Optional,Tuple,List,Dict,Any
from pydantic import BaseModel
from fastapi import Depends, FastAPI, Request, Security, status, Form
from fastapi.security import APIKeyHeader
from fastapi.exceptions import HTTPException,RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
#from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import sys
import asyncio
import datetime


import telephant_server.db
import telephant_server.auth



def create_app(config):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        taul = asyncio.create_task(telephant_server.asn.asn_update_loop())
        yield
        taul.cancel()

    app = FastAPI(root_path=config.get('root_path','/'), lifespan=lifespan)

## DEBUGGING FACILITY - remove from production code
    @app.exception_handler(Exception)
    async def exception_handler(request: Request, exc: Exception):
        exc_str = f'{exc}'.replace('\n', ' ').replace('   ', ' ')
        # or logger.error(f'{exc}')
        print(request, exc_str)
        content = {'status_code': 10422, 'message': exc_str, 'data': None}
        return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        exc_str = f'{exc}'.replace('\n', ' ').replace('   ', ' ')
        print(f"{request}: {exc_str}")
        content = {'status_code': 10422, 'message': exc_str, 'data': None}
        return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY) 



######################### This is protected by API KEY ############################
    def get_user_from_key(api_key: str =Security(APIKeyHeader(name="X-API-Key"))) -> telephant_server.db.User:
        user = telephant_server.db.verify_apikey_get_user(api_key)
        if user:
            return user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )

    class ReportData(BaseModel):
        report: str

    class ReportAccepted(BaseModel):
        report_id: int
        report_url: str


    @app.post("/api/v1/report", status_code=201)
    async def post_report(request: Request, data: ReportData, user: telephant_server.db.User =Security(get_user_from_key)) -> ReportAccepted:
        ts = datetime.datetime.utcnow()

        report_content = yaml.load(data.report, Loader=yaml.Loader)

        rdir = os.path.abspath(os.path.join(config.get('reports_dir','/telephant/reports'),f"{ts.year}-{ts.month}-{ts.day}"))
        if not os.path.exists(rdir):
            os.mkdir(rdir)
        rid, rfn = telephant_server.db.new_report(rdir, user, ts)
        with open(rfn, 'w') as fd:
            fd.write(data.report)

        telephant_server.db.index_report(rid, report_content)
        return ReportAccepted(report_id=rid, report_url=f"{config.get('url_base', 'http://localhost/').rstrip('/')}/report?showreport={rid}")
######################### End of part protected by API KEY ############################    


    import webcrud
    templates = Jinja2Templates(directory="templates")

    reportscrud = telephant_server.db.ReportsCRUD(app, templates, urlprefix=config.get('root_path', ''))
    reportscrud.generate_crud_endpoints()

    myreportscrud = telephant_server.db.MyReportsCRUD(app, templates, urlprefix=config.get('root_path', ''))
    myreportscrud.generate_crud_endpoints()

    groupscrud = telephant_server.db.GroupsCRUD(app, templates, urlprefix=config.get('root_path', ''))
    groupscrud.generate_crud_endpoints()

    apikeycrud = telephant_server.db.APIKeysCRUD(app, templates, urlprefix=config.get('root_path', ''))
    apikeycrud.generate_crud_endpoints()

    userscrud = telephant_server.db.UsersCRUD(app, templates, urlprefix=config.get('root_path', ''))
    userscrud.generate_crud_endpoints()

    def gen_basedata(request):
        u = telephant_server.auth.get_user_email(request)
        basedata = {"user" : u}
        if u and u in config.get('admins', {}):
            basedata['user_admin'] = True
        return basedata

    @app.get("/", response_class=HTMLResponse)
    async def get_root(request: Request, showreport: Optional[str] =None, showmessage: Optional[str] =None):
        if showreport:
            return RedirectResponse(url=f'/report?showreport={showreport}')

        pagedata = gen_basedata(request)
        if showmessage:
            pagedata['showmessage'] = showmessage
        return reportscrud.generate_template_response(request, pagedata, template='webcrudtable.html.j2')
    
    @app.get("/myreports", response_class=HTMLResponse)
    async def get_myreports(request: Request, showreport: Optional[str] =None):
        return myreportscrud.generate_template_response(request, gen_basedata(request), template='webcrudtable.html.j2')
    
    @app.get("/groups", response_class=HTMLResponse)
    async def get_groups(request: Request):
        return groupscrud.generate_template_response(request, gen_basedata(request), template='webcrudtable.html.j2')
    
    @app.get("/apikeys", response_class=HTMLResponse)
    async def get_apikeys(request: Request):
        return apikeycrud.generate_template_response(request, gen_basedata(request), template='webcrudtable.html.j2')
    
    @app.get("/users", response_class=HTMLResponse)
    async def get_users(request: Request):
        return userscrud.generate_template_response(request, gen_basedata(request), template='webcrudtable.html.j2')
    

    @app.get("/web/v1/reportdata/{rid}")
    async def get_reportdata(request: Request, rid: int) -> ReportData:
        r = telephant_server.db.get_report(int(rid))
        if r:
            with open(r.filename, 'r') as fd:
                return ReportData(report=fd.read())
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report {rid} not found",
            )

    @app.get("/report", response_class=HTMLResponse)
    async def get_reportweb(request: Request, showreport: Optional[str] =None):
        return templates.TemplateResponse("report.html.j2", gen_basedata(request)|{"request": request, "root_path": config.get('root_path', ''), "showreport": showreport})

    telephant_server.auth.create_auth(app, get_root)

    return app

app = create_app(config)


def main():
    import uvicorn
    uvicorn.run(app, host=config.get("listen_address", "127.0.0.1"), port=config.get("listen_port", 8080), proxy_headers=True)
    return 0

if __name__ == '__main__':
    sys.exit(main())