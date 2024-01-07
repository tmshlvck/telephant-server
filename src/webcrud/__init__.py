import typing
from typing import Annotated,Optional,Tuple,List,Dict,Any,Type,Callable
import inspect
from pydantic import BaseModel
from enum import Enum,EnumType
from datetime import datetime,date

from fastapi import Depends, FastAPI, Request, Security, status, Form
from fastapi.security import APIKeyHeader
from fastapi.exceptions import HTTPException,RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

class WebCRUD:
    APIVERSION = 1

    def __init__(self, app: FastAPI,
                 template_engine: Jinja2Templates,
                 cls:Type[BaseModel],
                 pagename:Optional[str] =None,
                 readonly: bool =False,
                 urlprefix: str ='',
                 formatting_hints:Dict[str,Any] ={}):
        """
        formatting_hints = {
            'struct_var_name' : {
                'default_value_js': None, # this has to be JavaScript statement or None
                'href':'/report?showreport=', # display text as hyperlink to this URL, row_idx will be added to the end
                'column_name': 'text name',
                'type': 'text|password',
                'preformat': False,
                'show_in_table': True,
                'show_in_edit': True,
                'readonly': False,
                'multiline': False, # this makes sense only for str / Optional[str] attrs
                'selector': "NameOfSelectorItem", # makes sense only for nested structures under Union type
                'selector_map': {'A': 'ARecord', 'selector_value': 'EnumTypeName'}
            },
            '__page__': { 'search_enabled': False, 'create_enabled': True, 'readonly': False}
        }
        """
        self.app = app
        self.template_engine = template_engine
        self.cls = cls
        if pagename:
            self.pagename = pagename
        else:
            self.pagename = self.cls.__name__
        self.readonly = readonly
        self.urlprefix = urlprefix
        self.formatting_hints = formatting_hints
        if self.readonly:
            if not '__page__' in self.formatting_hints:
                self.formatting_hints['__page__'] = {}
            self.formatting_hints['__page__']['readonly'] = True

    
    def generate_jinja_struct(self, input=None, parent_name=None):
        if input == None:
            input = self.cls.__annotations__

        def isunion(typevar):
            if type(typevar) is typing._UnionGenericAlias:
                return True
            else:
                return False

        def getunionopts(unionvar):
            if isunion(unionvar):
                return unionvar.__args__
            else:
                return None

        def fh_normalize(elfh, show_in_table_default:bool=True, **kwargs):
            res = elfh.copy()
            if not 'show_in_table' in res:
                res['show_in_table'] = show_in_table_default
 
            for k in kwargs:
                res[k] = kwargs[k]
            return res
        
        selectors = {}
        for eln in input:
            elfh = self.formatting_hints.get(eln,{})
            if isunion(input[eln]) and elfh.get('selector', None) in self.cls.__annotations__:
                selectors[elfh['selector']] = eln

        for eln in input:
            el = input[eln]
            if parent_name:
                eln = parent_name + '.' + eln

            elfh = self.formatting_hints.get(eln,{})

            #print(f"elfh={str(elfh)}")
            #print(f"DEBUG: {eln}: {el} ({type(el)})")
            #print(f"isuinion={isunion(el)}")

            if eln in selectors:
                elfh['__selector_for__'] = selectors[eln]

            if el == str or (isunion(el) and (str in getunionopts(el))):
                if elfh.get('multiline'):
                    yield (eln, 'textarea', fh_normalize(elfh, show_in_table_default=False))
                elif elfh.get('type'):
                    yield (eln, 'input', fh_normalize(elfh, type=elfh['type']))
                else:
                    yield (eln, 'input', fh_normalize(elfh, type='text'))
            elif el == int or (isunion(el) and (int in getunionopts(el))):
                yield (eln, 'input', fh_normalize(elfh, type='number'))

            elif el == bool or (isunion(el) and (bool in getunionopts(el))):
                yield (eln, 'switch', fh_normalize(elfh))

            elif el == List[int] or (isunion(el) and (List[int] in getunionopts(el))):
                yield (eln, 'list', fh_normalize(elfh, type='number'))

            elif el == List[str] or (isunion(el) and (List[str] in getunionopts(el))):
                yield (eln, 'list', fh_normalize(elfh, type='text'))

            elif el == datetime or (isunion(el) and (datetime in getunionopts(el))):
                yield (eln, 'input', fh_normalize(elfh, type='datetime-local'))

            elif el == date or (isunion(el) and (date in getunionopts(el))):
                yield (eln, 'input', fh_normalize(elfh, type='date'))

            elif isunion(el) and elfh.get('selector', None) in self.cls.__annotations__:
                elfh['default_value_js'] = '{}'
                elfh['show_in_edit'] = False
                yield (eln, 'list', fh_normalize(elfh))

                for uel in getunionopts(el):
                    selector_map_inv = dict((v,k) for k,v in elfh.get('selector_map', {}).items())
                    for seln, stype, selfh in self.generate_jinja_struct(uel.__annotations__, eln):
                        selfh['parent'] = eln
                        selfh['show_in_table'] = False
                        selfh['selector'] = elfh['selector']
                        selfh['selector_value'] = selector_map_inv.get(uel.__name__, None)
                        if selfh['selector_value'] == None:
                            selfh['selector_value'] = uel.__name__
                        yield (seln, stype, selfh)

            elif type(el) is typing._GenericAlias:
                # Can not process union consisting of non str/int/bool members and generic aliases. Moreover, we can not call issubclass(). Ignoring.
                pass

            elif inspect.isclass(el) and issubclass(el, Enum):
                options = {ee.name:ee.value for ee in el}
                yield (eln, 'select', fh_normalize(elfh, options=options))

            elif issubclass(el, BaseModel):
                raise NotImplementedError("Substructures are not implemented yet")
            else:
                raise ValueError(f"Unsupported type: {el}")

    def get_endpoint_path(self):
        return f'/web/v{self.APIVERSION}/'+self.cls.__name__.lower()

    def get_crud_url(self):
        return self.urlprefix.rstrip('/').strip()+self.get_endpoint_path()
    
    def generate_template_response(self, request, basedata={}, template=None):
        if not template:
            template = self.cls.__name__.lower()+".html.j2"

        jstr = list(self.generate_jinja_struct())
        #print(f"DEBUG: jstr= {str(jstr)}")
        return self.template_engine.TemplateResponse(template, basedata | {"request": request, "crudurl": self.get_crud_url(), "crudname": self.pagename, 'pageopts': self.formatting_hints.get('__page__', {}), "cruddef": jstr})


    def generate_backend_crud_endpoints(self,
                                        backend_search: Callable[[Request, int, int, Optional[str]], Tuple[List[Tuple[int,Type[BaseModel]]],int]],
                                        backend_get: Callable[[Request, int], Type[BaseModel]],
                                        backend_create: Optional[Callable[[Request, Type[BaseModel]], int]] =None,
                                        backend_update: Optional[Callable[[Request, int, Type[BaseModel]], None]] =None,
                                        backend_delete: Optional[Callable[[Request, int], None]] =None ):

        crudurl = '/web/v1/'+self.cls.__name__.lower()

        class Pagination(BaseModel):
            entries: List[Tuple[int,self.cls]]
            totalcount: int

        @self.app.get(crudurl)
        async def crud_ep_get_list(request: Request, page: int =0, pagelen: int =100, search: str ='') -> Pagination:
            offset = page*pagelen
            entries,totalcount = backend_search(request, offset, pagelen, search)
            return Pagination(entries=entries, totalcount=totalcount)

        @self.app.get(crudurl+'/{id}')
        async def crud_ep_get(request: Request, id:int) -> self.cls:
            return backend_get(request, id)

        if not self.readonly:
            @self.app.put(crudurl+'/{id}')
            async def crud_ep_put(request: Request, id:int, element:self.cls) -> None:
                backend_update(request, id, element)

            @self.app.delete(crudurl+'/{id}')
            async def crud_ep_put(request: Request, id:int) -> None:
                backend_delete(request, id)

            @self.app.post(crudurl)
            async def crud_ep_post(request: Request, element:self.cls) -> int:
                return backend_create(request, element)


class ListCRUD(WebCRUD):
    def generate_crud_endpoints(self,
                                data: List[Type[BaseModel]],
                                create_callback: Optional[Callable[[int, Type[BaseModel]], None]] =None,
                                update_callback: Optional[Callable[[int, Type[BaseModel]], None]] =None,
                                delete_callback: Optional[Callable[[int, Type[BaseModel]], None]] =None ):

        def search(_: Request, offset: int, count: int, search: Optional[str] =None) -> Tuple[List[Tuple[int,self.cls]],int]:
            nonlocal data
            sidx = min(max(0,offset),len(data)-1)
            eidx = min(sidx+count,len(data))
            return ([(sidx+i, e) for i,e in enumerate(self.data[sidx:eidx])], len(data))
        
        def get(_: Request, id: int) -> self.cls:
            nonlocal data
            return self.data[id]


        def create(_: Request, element: self.cls):
            nonlocal data
            self.data.append(element)
            newid = len(self.data)
            if create_callback:
                create_callback(element, newid)
            return newid
        
        def update(_: Request, id: int, element: self.cls):
            nonlocal data
            self.data[id] = element
            if update_callback:
                update_callback(id, element)

        def delete(_: Request, id: int):
            nonlocal data
            element = self.data.pop(id)
            if delete_callback:
                delete_callback(id, element)

        self.generate_backend_crud_endpoints(search, get, create, update, delete)




def test():
    class SelectTest(Enum):
        test1 = 'teststr1'
        test2 = 'teststr2'

    class Example(BaseModel):
        a: str
        b: int
        c: SelectTest

    ex = [Example(a='test', b=10, c=SelectTest.test1),]
    app = FastAPI()
    j2 = Jinja2Templates(directory="templates")
    crud = ListCRUD(j2, Example)
    crud.generate_crud_endpoints(app, Example, ex, None, None)

if __name__ == '__main__':
    test()
