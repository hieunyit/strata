import { beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { apiClient, Event, EventCase, SavedSearch } from '../api/client';
import { EventInvestigation } from '../components/events/EventInvestigation';
import { InvestigationSearchPanel } from '../components/events/InvestigationSearchPanel';
import { StaticAuthProvider } from '../context/AuthContext';
import { toCsv } from '../lib/csv';
import i18n from '../i18n';
import { EventsPage } from '../pages/EventsPage';

const event: Event = { block_id:'STR-0000-0000-0000-0001', timestamp:'2026-10-21T00:00:00Z', node_id:'node-a',connector_type:'nginx',policy_id:'example-api',policy_version:1,client_ip:'198.51.100.0/24',http_method:'GET',http_host:'api.example.test',http_path:'/api/search',status_code:403,action:'block',geoip_version:'synthetic-test',country_iso:'VN' };
const value: EventCase = { block_id:event.block_id,assignee:'',status:'open',note:'',etag:'case-etag',expires_at:'2026-11-21T00:00:00Z' };
const filter = {from:'2026-10-20T00:00:00Z',to:'2026-10-21T00:00:00Z'};
beforeEach(()=>{
 vi.restoreAllMocks();void i18n.changeLanguage('en');
 vi.spyOn(apiClient,'eventCase').mockResolvedValue(value);
 vi.spyOn(apiClient,'listPolicies').mockResolvedValue([{id:'policy-api',name:'example-api',etag:'policy-etag',version:1}]);
 vi.spyOn(apiClient,'listApplications').mockResolvedValue({applications:[{id:'example-api',name:'Example',owner:'operator',etag:'app-etag',created_at:'2026-10-21T00:00:00Z',updated_at:'2026-10-21T00:00:00Z',environments:[{id:'test',name:'Test',group_id:'example-group'}],routes:[]}],next_cursor:''});
 vi.spyOn(apiClient,'evidenceList').mockResolvedValue({exports:[]});
 vi.spyOn(apiClient,'savedSearches').mockResolvedValue({searches:[],next_cursor:''});
});
it('shows investigation state to viewers and hides case/rule writes',async()=>{
 render(<StaticAuthProvider roles={['viewer']}><EventInvestigation event={event}/></StaticAuthProvider>);
 expect(await screen.findByLabelText('Status')).toBeDisabled();expect(screen.queryByRole('button',{name:'Save case'})).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Propose geo rule'})).not.toBeInTheDocument();
});
it('keeps case etag and command stable after an uncertain outcome',async()=>{
 const save=vi.spyOn(apiClient,'saveEventCase').mockRejectedValueOnce(new Error('lost reply')).mockResolvedValue({...value,status:'investigating',etag:'new-etag'});
 render(<StaticAuthProvider roles={['operator']}><EventInvestigation event={event}/></StaticAuthProvider>);
 fireEvent.change(await screen.findByLabelText('Status'),{target:{value:'investigating'}});fireEvent.click(screen.getByRole('button',{name:'Save case'}));await screen.findByRole('alert');
 expect(screen.getByLabelText('Status')).toBeDisabled();fireEvent.click(screen.getByRole('button',{name:'Save case'}));await waitFor(()=>expect(save).toHaveBeenCalledTimes(2));expect(save.mock.calls[1]).toEqual(save.mock.calls[0]);expect(save.mock.calls[0][0].etag).toBe('case-etag');
});
it('creates only a draft and sends the current policy etag',async()=>{
 const propose=vi.spyOn(apiClient,'proposeEventRule').mockResolvedValue({policy_id:'policy-api',policy_version:2,etag:'new',state:'DRAFT',replay_url:'/v1/policies/policy-api/versions/2/replay'});
 render(<StaticAuthProvider roles={['operator']}><EventInvestigation event={event}/></StaticAuthProvider>);
 const button=await screen.findByRole('button',{name:'Propose geo rule'});await waitFor(()=>expect(button).toBeEnabled());fireEvent.click(button);expect(await screen.findByText('Draft version 2 created.')).toBeInTheDocument();expect(propose).toHaveBeenCalledWith(event.block_id,{dimension:'country',action:'log',etag:'policy-etag',request_id:expect.any(String)});
});
it('uses an opaque share link and scopes evidence to the selected environment',async()=>{
 const saved: SavedSearch={id:'opaque-id',application_id:'example-api',environment_id:'test',owner:'operator',title:'Case A',shared:true,sensitive:false,filter,etag:'saved-etag',expires_at:'2026-12-21T00:00:00Z'};
 const save=vi.spyOn(apiClient,'saveSearch').mockResolvedValue(saved);
 render(<InvestigationSearchPanel filter={{...filter,client_ip:'198.51.100.42'}}/>);
 await screen.findByRole('option',{name:'Example'});fireEvent.change(screen.getByLabelText('Application'),{target:{value:'example-api'}});fireEvent.change(screen.getByLabelText('Environment'),{target:{value:'test'}});fireEvent.change(screen.getByLabelText('Search title'),{target:{value:'Case A'}});fireEvent.click(screen.getByLabelText('Share with authorized users'));fireEvent.click(screen.getByRole('button',{name:'Save current filter'}));
 await waitFor(()=>expect(save).toHaveBeenCalledTimes(1));await waitFor(()=>expect(window.location.hash).toBe('#/events?saved=opaque-id'));expect(window.location.hash).not.toContain('198.51');expect(save.mock.calls[0][0].environment_id).toBe('test');
});
it('neutralizes formula prefixes hidden behind whitespace or BOM',()=>{
 for(const value of ['  =cmd()','\ufeff@SUM(A1)','\n+1'])expect(toCsv(['cell'],[[value]]).split('\r\n')[1]).toContain("'");
});

it('clears the saved time window when the user applies new filters',async()=>{
 vi.spyOn(apiClient,'getVersion').mockResolvedValue({version:'test'});
 vi.spyOn(apiClient,'savedSearch').mockResolvedValue({id:'opaque-id',application_id:'example-api',environment_id:'test',owner:'operator',title:'Case A',shared:true,sensitive:false,filter,etag:'saved-etag',expires_at:'2026-12-21T00:00:00Z'});
 const saved=vi.spyOn(apiClient,'searchSavedEvents').mockResolvedValue({events:[],total_matched:0});
 const ordinary=vi.spyOn(apiClient,'searchEvents').mockResolvedValue({events:[],total_matched:0});
 render(<StaticAuthProvider roles={['operator']}><EventsPage route={{page:'events',query:{saved:'opaque-id'}}}/></StaticAuthProvider>);
 await waitFor(()=>expect(saved).toHaveBeenCalled());expect(await screen.findByText('Saved time window')).toBeInTheDocument();
 fireEvent.click(screen.getByTestId('reset-filters-btn'));await waitFor(()=>expect(ordinary).toHaveBeenCalled());expect(screen.queryByText('Saved time window')).not.toBeInTheDocument();expect(screen.queryByText('Open share link')).not.toBeInTheDocument();
});

it('allows the owner to make an existing shared search private',async()=>{
 const saved: SavedSearch={id:'opaque-id',application_id:'example-api',environment_id:'test',owner:'operator',title:'Case A',shared:true,sensitive:false,filter,etag:'saved-etag',expires_at:'2026-12-21T00:00:00Z',editable:true};
 vi.spyOn(apiClient,'savedSearch').mockResolvedValue(saved);const save=vi.spyOn(apiClient,'saveSearch').mockResolvedValue({...saved,shared:false});
 render(<InvestigationSearchPanel filter={filter} savedId="opaque-id"/>);
 const toggle=await screen.findByLabelText('Share with authorized users');await waitFor(()=>expect(toggle).toBeChecked());fireEvent.click(toggle);fireEvent.click(screen.getByRole('button',{name:'Update saved search'}));
 await waitFor(()=>expect(save).toHaveBeenCalledWith(expect.objectContaining({id:'opaque-id',etag:'saved-etag',shared:false}),expect.any(String),false));
});
