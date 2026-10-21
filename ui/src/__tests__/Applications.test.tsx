import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import '../i18n';
import {StaticAuthProvider} from '../context/AuthContext';
import {ApplicationsPage} from '../pages/ApplicationsPage';
import {apiClient,Application} from '../api/client';
const app:Application={id:'example-api',name:'Example API',owner:'Team',etag:'e',created_at:'2026-10-01T00:00:00Z',updated_at:'2026-10-20T00:00:00Z',environments:[{id:'prod',name:'Production',group_id:'edge'}],routes:[{id:'api',environment_id:'prod',host:'api.example.test',path_prefix:'/',policy_id:'p1',schema_id:''}]};
describe('Applications',()=>{
 it('shows scoped event totals and does not infer inspection coverage',async()=>{
 vi.spyOn(apiClient,'listApplications').mockResolvedValue({applications:[app],next_cursor:''});
 vi.spyOn(apiClient,'listApplicationBindings').mockResolvedValue({bindings:[]});
 vi.spyOn(apiClient,'applicationOverview').mockResolvedValue({from:'',to:'',step_seconds:60,totals:{events:3,block:2,shadow:1,other:0,error:0,clients:1,nodes:1,policies:1,requests:0},series:[],top_rules:[],top_routes:[],inspection:[],telemetry_scope:'events_only'});
 render(<StaticAuthProvider roles={['viewer']}><ApplicationsPage/></StaticAuthProvider>);
 fireEvent.click(await screen.findByText('Example API · Team'));
 expect(await screen.findByTestId('application-stats')).toBeTruthy();
 expect(screen.getByText(/request counters do not include route dimensions|bộ đếm request chưa phân chia/)).toBeTruthy();
 expect(screen.queryByTestId('application-editor')).toBeNull();
 expect(apiClient.applicationOverview).toHaveBeenCalledWith('example-api',expect.any(String),expect.any(String),'');
 });
 it('sends generated typed application and request ID when creating',async()=>{
 vi.spyOn(apiClient,'listApplications').mockResolvedValue({applications:[],next_cursor:''});
 vi.spyOn(apiClient,'saveApplication').mockResolvedValue({application:app});
 render(<StaticAuthProvider roles={['operator']}><ApplicationsPage/></StaticAuthProvider>);
 fireEvent.click(await screen.findByText(/Create application|Tạo ứng dụng/));
 const form=screen.getByTestId('application-editor');
 fireEvent.change(form.querySelectorAll('input')[0],{target:{value:'example-api'}});
 fireEvent.change(form.querySelectorAll('input')[1],{target:{value:'Example API'}});
 fireEvent.change(form.querySelectorAll('input')[2],{target:{value:'Team'}});
 fireEvent.click(screen.getByText(/^Save$|^Lưu$/));
 await waitFor(()=>expect(apiClient.saveApplication).toHaveBeenCalledWith(expect.objectContaining({id:'example-api',owner:'Team'}),true,expect.any(String)));
 });
});
