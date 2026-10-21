import { beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { apiClient, ExceptionInventoryPage, RuleCatalogPage } from '../api/client';
import { StaticAuthProvider } from '../context/AuthContext';
import { RulesPage } from '../pages/RulesPage';
import { ExceptionsPage } from '../pages/ExceptionsPage';
import i18n from '../i18n';

const digest='a'.repeat(64), previous='b'.repeat(64);
const catalog: RuleCatalogPage={rules:[{id:700011,name:'Example virtual patch',pack:'core',digest,source:'strata',version:'1.2',cves:['CVE-2026-12345'],owner:'example-team'}],next_cursor:0,digest,at:'2026-10-21T00:00:00Z',stale:false,source:'configured_catalog',total:1};
const exceptions: ExceptionInventoryPage={exceptions:[{policy_id:'policy-api',policy_name:'example-api',policy_version:2,etag:'policy-etag',exception:{id:'exc-0123456789abcdef0123456789abcdef',rule_id:700011,method:'POST',host:'api.example.test',path:'/api/search',field:'ARGS:q',expires_unix_ms:1792540800000,reason:'example'},origin:{owner:'oidc:operator',created_at:'2026-10-20T00:00:00Z'},state:'DRAFT',decided_by:'',approved_replay_id:'',warnings:['expired'],match_source:'not_collected',unused_status:'unknown',editable:true,active_nodes:0}],maintenance:[],next_cursor:'',at:'2026-10-21T00:00:00Z'};
beforeEach(()=>{
 vi.restoreAllMocks();void i18n.changeLanguage('en');
 vi.spyOn(apiClient,'getVersion').mockResolvedValue({version:'test'});
 vi.spyOn(apiClient,'listApplications').mockResolvedValue({applications:[{id:'example-api',name:'Example',owner:'operator',etag:'app-etag',created_at:'2026-10-21T00:00:00Z',updated_at:'2026-10-21T00:00:00Z',environments:[{id:'test',name:'Test',group_id:'example-group'}],routes:[]}],next_cursor:''});
 vi.spyOn(apiClient,'ruleCatalog').mockResolvedValue(catalog);
 vi.spyOn(apiClient,'catalogHistory').mockResolvedValue([{digest:previous,created_at:'2026-10-20T00:00:00Z',last_seen_at:'2026-10-20T00:00:00Z',current:false,rules:1}]);
 vi.spyOn(apiClient,'exceptions').mockResolvedValue(exceptions);
});
async function scope(){await screen.findByRole('option',{name:'Example'});fireEvent.change(screen.getByRole('combobox',{name:'Application'}),{target:{value:'example-api'}});fireEvent.change(screen.getByRole('combobox',{name:'Environment'}),{target:{value:'test'}});}
it('shows rule provenance and keeps cost unknown when no measurement exists',async()=>{
 vi.spyOn(apiClient,'ruleCatalogDetail').mockResolvedValue({rule:catalog.rules[0],usage:[],health:null,health_status:'unavailable'});
 render(<StaticAuthProvider roles={['viewer']}><RulesPage/></StaticAuthProvider>);
 expect(await screen.findByText('CVE-2026-12345')).toBeInTheDocument();await scope();fireEvent.click(screen.getByRole('button',{name:'700011 · Example virtual patch'}));await screen.findByText('Sampled mean rule cost: Unknown');expect(screen.queryByText('0.0 ns')).not.toBeInTheDocument();
});
it('compares content changes for retained rule IDs',async()=>{
 const compare=vi.spyOn(apiClient,'catalogDiff').mockResolvedValue({added:0,removed:0,modified:1,changes:[{id:700011,kind:'modified',before:{name:'Old',pack:'core',digest:previous,version:'1.1'},after:catalog.rules[0]}],next_cursor:0});
 render(<StaticAuthProvider roles={['viewer']}><RulesPage/></StaticAuthProvider>);await screen.findByText('CVE-2026-12345');fireEvent.change(screen.getByRole('combobox',{name:'Baseline snapshot'}),{target:{value:previous}});fireEvent.click(screen.getByRole('button',{name:'Compare'}));await screen.findByText('Added 0, removed 0, modified 1.');expect(compare).toHaveBeenCalledWith(previous,digest,'');
});
it('hides lifecycle writes when the server denies policy mutation',async()=>{
 vi.mocked(apiClient.exceptions).mockResolvedValue({...exceptions,exceptions:exceptions.exceptions.map((v)=>({...v,editable:false,exception:{...v.exception,reason:''}}))});
 render(<StaticAuthProvider roles={['viewer']}><ExceptionsPage/></StaticAuthProvider>);await scope();await screen.findByText('Expired at runtime');expect(screen.queryByRole('button',{name:'Create revocation draft'})).not.toBeInTheDocument();expect(screen.getByText('Exception hit telemetry is not collected; usage is unknown.')).toBeInTheDocument();
});
it('retains the exact revoke command after an uncertain response',async()=>{
 const revoke=vi.spyOn(apiClient,'exceptionLifecycle').mockRejectedValueOnce(new Error('reply lost')).mockResolvedValue({policy_id:'policy-api',policy_version:3,etag:'new',state:'DRAFT',replay_url:'/v1/policies/policy-api/versions/3/replay'});
 render(<StaticAuthProvider roles={['operator']}><ExceptionsPage/></StaticAuthProvider>);await scope();fireEvent.click(await screen.findByRole('button',{name:'Create revocation draft'}));await screen.findByRole('alert');fireEvent.click(screen.getByRole('button',{name:'Create revocation draft'}));await screen.findByText('Draft version 3 created.');expect(revoke.mock.calls[1]).toEqual(revoke.mock.calls[0]);expect(revoke.mock.calls[0][1].etag).toBe('policy-etag');
});
