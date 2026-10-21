import {beforeEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import {apiClient,DiscoveryInventory,DiscoveryProposal} from '../api/client';
import {StaticAuthProvider} from '../context/AuthContext';
import {DiscoveryPage} from '../pages/DiscoveryPage';
import i18n from '../i18n';
const digest='a'.repeat(64),key='b'.repeat(64);
const operation={path:'/api/users/{param1}',method:'POST' as const,content_types:['application/json'],max_body_bytes:65536};
const endpoint={key,route_id:'api',path:operation.path,method:'POST',content_types:['application/json'],samples:20,independent_sources:3,first_seen:'2026-10-21T00:00:00Z',last_seen:'2026-10-21T00:20:00Z',observed_max_body_bytes:234,eligible:true};
const proposal:DiscoveryProposal={id:'proposal-a',application_id:'example-api',environment_id:'test',route_id:'api',base_digest:digest,operations:[operation],digest:key,evidence:endpoint,changes:[{path:operation.path,method:'POST',kind:'added',before:null,after:operation}],etag:'proposal-etag',owner:'oidc:operator',created_at:'2026-10-21T00:00:00Z',expires_at:'2026-11-21T00:00:00Z',draft_policy_id:'',draft_version:0,review_state:'PROPOSED',policy_id:'policy-api',policy_etag:'policy-etag',policy_version:1,draftable:true};
const inventory:DiscoveryInventory={endpoints:[endpoint],document:{application_id:'example-api',environment_id:'test',etag:'doc-etag',operations:[],digest,updated_at:'2026-10-21T00:00:00Z',owner:'oidc:operator'},document_etag:'doc-etag',scope_changed:false,proposals:[],editable:true,collection_enabled:false,approval_expires_at:null,runtime_enforcement:false,source:'trusted_backend_2xx_only',limits:{min_samples:20,min_sources:3,min_span_seconds:600,retention_days:7}};
beforeEach(()=>{vi.restoreAllMocks();void i18n.changeLanguage('en');vi.spyOn(apiClient,'getVersion').mockResolvedValue({version:'test'});vi.spyOn(apiClient,'listApplications').mockResolvedValue({applications:[{id:'example-api',name:'Example',owner:'operator',etag:'app-etag',created_at:'2026-10-21T00:00:00Z',updated_at:'2026-10-21T00:00:00Z',environments:[{id:'test',name:'Test',group_id:'example-group'}],routes:[]}],next_cursor:''});vi.spyOn(apiClient,'apiDiscovery').mockResolvedValue(inventory);});
async function scope(){await screen.findByRole('option',{name:'Example'});fireEvent.change(screen.getByRole('combobox',{name:'Application'}),{target:{value:'example-api'}});fireEvent.change(screen.getByRole('combobox',{name:'Environment'}),{target:{value:'test'}});}
it('states legal/runtime limits and hides viewer mutations',async()=>{
 vi.mocked(apiClient.apiDiscovery).mockResolvedValue({...inventory,editable:false});render(<StaticAuthProvider roles={['viewer']}><DiscoveryPage/></StaticAuthProvider>);await scope();await screen.findByText('Collection is disabled or approval has expired.');expect(screen.getByRole('note')).toHaveTextContent('This runtime does not enforce OpenAPI.');expect(screen.queryByRole('button',{name:'Propose changes'})).not.toBeInTheDocument();
});
it('keeps ineligible endpoints out of proposals',async()=>{
 vi.mocked(apiClient.apiDiscovery).mockResolvedValue({...inventory,endpoints:[{...endpoint,eligible:false,samples:2}]});render(<StaticAuthProvider roles={['operator']}><DiscoveryPage/></StaticAuthProvider>);await scope();expect(await screen.findByRole('button',{name:'Propose changes'})).toBeDisabled();
});
it('retries the same proposal then drafts the observed policy revision',async()=>{
 const propose=vi.spyOn(apiClient,'proposeDiscovery').mockRejectedValueOnce(new Error('reply lost')).mockResolvedValue(proposal);const draft=vi.spyOn(apiClient,'draftDiscovery').mockResolvedValue({policy_id:'policy-api',policy_version:2,etag:'next',state:'DRAFT',replay_url:'/v1/policies/policy-api/versions/2/replay'});
 render(<StaticAuthProvider roles={['operator']}><DiscoveryPage/></StaticAuthProvider>);await scope();fireEvent.click(await screen.findByRole('button',{name:'Propose changes'}));await screen.findByRole('alert');fireEvent.click(screen.getByRole('button',{name:'Propose changes'}));fireEvent.click(await screen.findByRole('button',{name:'Create draft and replay'}));await screen.findByText('Draft version 2 created.');expect(propose.mock.calls[0]).toEqual(propose.mock.calls[1]);expect(draft).toHaveBeenCalledWith(expect.objectContaining({id:'proposal-a',etag:'proposal-etag',policy_etag:'policy-etag'}));
});
it('lets a reviewer inspect the proposal-bound revision alongside its immutable diff',async()=>{
 vi.mocked(apiClient.apiDiscovery).mockResolvedValue({...inventory,editable:false,proposals:[{...proposal,draft_policy_id:'policy-api',draft_version:2,review_state:'SUBMITTED',draftable:false}]});
 vi.spyOn(apiClient,'listPolicyVersions').mockResolvedValue([{policy_id:'policy-api',version:2,state:'SUBMITTED',spec:{mode:'MODE_SHADOW'},created_by:'operator',submitted_by:'operator'}]);const replay=vi.spyOn(apiClient,'getVersionReplay').mockResolvedValue(undefined);
 render(<StaticAuthProvider roles={['viewer']}><DiscoveryPage/></StaticAuthProvider>);await scope();fireEvent.click(await screen.findByRole('button',{name:'Review draft and replay'}));await screen.findByText('No replay has been queued for this version.');expect(replay).toHaveBeenCalledWith('policy-api',2,expect.any(AbortSignal));expect(screen.queryByRole('button',{name:'Approve'})).not.toBeInTheDocument();
});
