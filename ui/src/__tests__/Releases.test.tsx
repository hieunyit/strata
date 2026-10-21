import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {describe,it,expect,vi,beforeEach} from 'vitest';
import '../i18n';
import {ReleasesPage} from '../pages/ReleasesPage';
import {StaticAuthProvider} from '../context/AuthContext';
import {apiClient,Release} from '../api/client';
const release:Release={id:'release-a',etag:'e1',state:'APPROVED',snapshot_hash:'abc',source_release:'',created_by:'operator',created_subject:'local:operator',approved_by:'reviewer',created_at:'',updated_at:'',bundle_version:'0',rollout_id:0,snapshot:{bundle:{contents:{'example-api':1},input_digest:'inputs',rules_digest:'rules'},baseline_bundle:'1',replay_ids:{},replay_baseline_mismatch:true,canary:{},waves:[0,1],soak_seconds:30}};
beforeEach(()=>{vi.restoreAllMocks();vi.spyOn(apiClient,'listReleases').mockResolvedValue({releases:[release],next_cursor:''});});
describe('release workflow',()=>{
 it('requires explicit baseline acknowledgement before deploy',async()=>{
 vi.spyOn(apiClient,'getRelease').mockResolvedValue({release,current_baseline:'43',baseline_warning:true});
 vi.spyOn(apiClient,'actRelease').mockResolvedValue({release:{...release,state:'DEPLOYED'}});
 render(<StaticAuthProvider roles={['operator']}><ReleasesPage/></StaticAuthProvider>);
 fireEvent.click(await screen.findByText(/release-a ·/));
 const deploy=await screen.findByText(/Deploy approved release|Triển khai release đã duyệt/);
 expect(deploy).toBeDisabled();
 fireEvent.click(screen.getByRole('checkbox'));
 expect(deploy).toBeEnabled();fireEvent.click(deploy);
 await waitFor(()=>expect(apiClient.actRelease).toHaveBeenCalledWith('release-a','deploy',expect.objectContaining({etag:'e1',ack_baseline:'43'})));
 });
 it('viewer gets immutable metadata but no write buttons',async()=>{
 vi.spyOn(apiClient,'getRelease').mockResolvedValue({release,current_baseline:'43',baseline_warning:true});
 render(<StaticAuthProvider roles={['viewer']}><ReleasesPage/></StaticAuthProvider>);
 fireEvent.click(await screen.findByText(/release-a ·/));await screen.findByTestId('release-detail');
 expect(screen.queryByText(/^Deploy approved release$|^Triển khai release đã duyệt$/)).toBeNull();
 expect(screen.queryByText(/^Prepare release$|^Chuẩn bị release$/)).toBeNull();
 });
});
